Return-Path: <kasan-dev+bncBCT4XGV33UIBB2O7Q7DAMGQE5G32Z2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id C9D0EB52396
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 23:38:51 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id d2e1a72fcca58-76e6e71f7c6sf54934b3a.0
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Sep 2025 14:38:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757540330; cv=pass;
        d=google.com; s=arc-20240605;
        b=LqlwP3j0EpbZGAWLoQDhfD8bHylbROPbQ4ZlNZi7FvkSGZz3lbirfjJ8XPdgnweM9X
         LewmaHjE8m14CXb7D6++TBQaVYfqdbYaubTdpQtD1B9pELCKcvkOpBFfOOPWoNjndPev
         Usx9ZuCd8yXu6+7wl3kXfjVdijDNEledIFJJkETrNQ5G2V5r0pVbA6kH0ATex43YxrAI
         CbEv9iz1N37Qf/yugKekt5n8aLHiYaGtJdwjcHZ51zXnNUbhqnO1B4xFURJ18PlR+FF7
         ZsQNx5R6qhTtzPd1xtex2KyT6StPUa7BDqiU7kSpMuotF0W2pgK3zpwul5mt3g55GqKi
         oeWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=UfPiGQUF/RkCl182qdhYuVVLC4XFdnKAQx9DYMnQu5w=;
        fh=hzyoqyKU+9u8xtCxpMbNQ+bm2MmtDvigAYGGCZ2laFc=;
        b=Tl/v/83U6fPoAcA2q4Pf1s7OWGGtkSlGVDZxOiulhCIg4yNTab8W/w5aQ8IVEi6MYF
         YB3vCqgFj5qUvYTUpZk0pvMrA+CyN3L9li8JG758sQAlu17yv8wH+gJiESemy52cRWox
         52IUhXPmvhIfCly6DgJn70sVqAIhPmVAOC8uzsFgEZxsiAQQqsu59b9njeRooXQdgNRV
         Ychcjc78W8QsPSXK43ffQNFYzVkhov36ySC1KpPBCbyCn7pSdStgVOVGsJvHjVcjX0Uz
         6dqUmHCQHq3RiawjlbEaG93eNvNInM/MeLBWaCGQzP0jCvirV0nJJ6DlEOR5th06A6ig
         yVAA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=ERlNyzA+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757540330; x=1758145130; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UfPiGQUF/RkCl182qdhYuVVLC4XFdnKAQx9DYMnQu5w=;
        b=jg0wOzidBJ2Hgdaux+GDfICXVAvLSCcMvUPaNPUtzU9ToUHKvivUjyRygqMukikjCT
         qHPqYCHSbOyXald6/affVdlAtqe6zJczZW7d0GZuQRYjLSocHli66r529nGhG+PhQHj9
         1cOzWFeInVlrFP5lzf5N9VzH1NNn4K3zN8xg16jSGTXJLZMXMCs0tvMpTZZBcYaJKHbD
         ClfjnmwlcARwiZ6l/Ff4Ns27Gi/fZnsaBAm6mFjZ1Fbyv+PsrL64n9HE2Ku4LwikXWZC
         nJQ/CIoTkjF7B9vzfu4zeHMlvCTC/6FQdkt5WgSAvK5cs0ketWF1074766nfM7TVC0hz
         lNaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757540330; x=1758145130;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UfPiGQUF/RkCl182qdhYuVVLC4XFdnKAQx9DYMnQu5w=;
        b=WioIdCmqfDVNzciYsNRfSCa3RFcc7RaDdKUm1IUxS46FmHY5feBZwqSx2KRDPYKoby
         0F/EdRe7viXCocbAKyskGnkuHjpMehUhPDJ59QTfRBU0WG7CymP8UUxox5E52FGwIouI
         qIYug95hJk2a1Ax0BgqhwvGLFFxfjF9MoiA1jDyMPxC9BiZiqWS9nwRG4ozHwdLY0FoG
         Jc7INnzwb3+bbKpaqb5KXALeTVp4uGpLc4evIlbVC+mycY5orxlME8VFgE+PiUHR5uKb
         1f5q4M0AImF2HdtWf8IwTqEPODDoYWCB4CxNvZ/rmhUCD8jr1nLc7rrgANFOIO5V11d9
         tMKQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXlxvcL0GuGbBr9FnMv3w4w5xxQHEy9T+5T17KJJoWrQYUV6QmSqEIscPeQp0caDKP0DMsZ2A==@lfdr.de
X-Gm-Message-State: AOJu0YwhkzbwYMIXfGAPCtrdNJj4fWyTHuYJLveeSDYNGT1dyMZtw8e3
	k8mkM9TS6NDLAHLiJq8eAC49NSAAPsbqFQ7VrIjMS+wOGECLPW+OuxLp
X-Google-Smtp-Source: AGHT+IFPY0iz/OOfmEYtyGNEh3KVgC2iDU3dfuWcoPdGBJjFZ9JCCeO8RUpneS+MR4lnuaKeCKzUaQ==
X-Received: by 2002:a05:6a00:22c8:b0:772:554c:4879 with SMTP id d2e1a72fcca58-7742de28f19mr18483142b3a.26.1757540330089;
        Wed, 10 Sep 2025 14:38:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcaITVM2JWwlfmq25oQcAndtvU1IuFhkyiXzShb1ZxymQ==
Received: by 2002:a05:6a00:3a10:b0:772:62f1:6058 with SMTP id
 d2e1a72fcca58-7760513ae46ls65849b3a.1.-pod-prod-01-us; Wed, 10 Sep 2025
 14:38:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWnmDEoA+aJ9eMV3aIwfKsIhmpYeN5P6/V+qeQYRfIX5zzOonUyyMmTNE5EWejWrjRHVPAhiI2MYkI=@googlegroups.com
X-Received: by 2002:a05:6a00:2d9d:b0:772:6c1a:7f18 with SMTP id d2e1a72fcca58-7742de26479mr18587105b3a.27.1757540328419;
        Wed, 10 Sep 2025 14:38:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757540328; cv=none;
        d=google.com; s=arc-20240605;
        b=Nv/dd7UTMgXTpPGdx3AdDs7cgKQJG5kywCLPx8PHpZEza/OmQtT0ZxMzGZQ5iX1vim
         TswLYdit2czHUDObvHc3+KnmCSGsCiBXTOyrkAVoVENSTeLM/geZY5r4ec5t990UNjvX
         YyhrpQaVOz8bh5UvzUBKjrfTXF4Bfk5Ji5DPjDqWChhedpdEL5oFTU39FYHOxT8kZSiN
         xwqNzXLx+6L3gVB8nueVgGtQ1W6Xd1NeE6Dr31OmxL1Q58rYw+rtYX66h450BcXJqohu
         rvBU4xbPyibTXCx90J0QQX6Ct2BNtbN97sVMRwGP/5iIwWss24EjkwG1lzv19o14+zlT
         LZXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=S4ITsVV/t8NbwT/7z/WdcHjGwXQmr80hXTyJJR6KQFs=;
        fh=YVZO3JAhXeTpoOPqkObmTEraZtOiU73pz+aG6ZbPp2s=;
        b=V7wcS7rKZtO5vHpba7BqlODZ+T6ZU5VeKcE5gdnzGV+Mi21h1h4pthhpb7RG/bzKsl
         nxFvAgG3URjntEi7B0GxRrWFLVyAiF9lXSVTFsDB70Ll7gPZOes7OdbA2sO1LZlvAuvX
         h583p8v312E5csbuxOTD9iXaisWeHJfpGt6ddOoaShlRCYLKkoSCwxyahc5yvYZyIMig
         CIxt7nDgWrNGIaBT+fKujyK1m2ZJ/rTU6p4B4m6Pol1UIi85HNZ2EXw5ubaaFhvAffqb
         LlBRcdQkln8DSaQfSKxOLe/uMeJ77WtjpN78QW/EyUq8PmukRi3vfbrw8IUM6DaiKKFP
         lnEQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=ERlNyzA+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-77246129c24si749358b3a.5.2025.09.10.14.38.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Sep 2025 14:38:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 012C8444CE;
	Wed, 10 Sep 2025 21:38:48 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 16257C4CEEB;
	Wed, 10 Sep 2025 21:38:46 +0000 (UTC)
Date: Wed, 10 Sep 2025 14:38:45 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Jonathan Corbet <corbet@lwn.net>, Matthew Wilcox <willy@infradead.org>,
 Guo Ren <guoren@kernel.org>, Thomas Bogendoerfer
 <tsbogend@alpha.franken.de>, Heiko Carstens <hca@linux.ibm.com>, Vasily
 Gorbik <gor@linux.ibm.com>, Alexander Gordeev <agordeev@linux.ibm.com>,
 Christian Borntraeger <borntraeger@linux.ibm.com>, Sven Schnelle
 <svens@linux.ibm.com>, "David S . Miller" <davem@davemloft.net>, Andreas
 Larsson <andreas@gaisler.com>, Arnd Bergmann <arnd@arndb.de>, Greg
 Kroah-Hartman <gregkh@linuxfoundation.org>, Dan Williams
 <dan.j.williams@intel.com>, Vishal Verma <vishal.l.verma@intel.com>, Dave
 Jiang <dave.jiang@intel.com>, Nicolas Pitre <nico@fluxnic.net>, Muchun Song
 <muchun.song@linux.dev>, Oscar Salvador <osalvador@suse.de>, David
 Hildenbrand <david@redhat.com>, Konstantin Komarov
 <almaz.alexandrovich@paragon-software.com>, Baoquan He <bhe@redhat.com>,
 Vivek Goyal <vgoyal@redhat.com>, Dave Young <dyoung@redhat.com>, Tony Luck
 <tony.luck@intel.com>, Reinette Chatre <reinette.chatre@intel.com>, Dave
 Martin <Dave.Martin@arm.com>, James Morse <james.morse@arm.com>, Alexander
 Viro <viro@zeniv.linux.org.uk>, Christian Brauner <brauner@kernel.org>, Jan
 Kara <jack@suse.cz>, "Liam R . Howlett" <Liam.Howlett@oracle.com>,
 Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>, Suren
 Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, Hugh
 Dickins <hughd@google.com>, Baolin Wang <baolin.wang@linux.alibaba.com>,
 Uladzislau Rezki <urezki@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Jann Horn <jannh@google.com>,
 Pedro Falcato <pfalcato@suse.de>, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-csky@vger.kernel.org, linux-mips@vger.kernel.org,
 linux-s390@vger.kernel.org, sparclinux@vger.kernel.org,
 nvdimm@lists.linux.dev, linux-cxl@vger.kernel.org, linux-mm@kvack.org,
 ntfs3@lists.linux.dev, kexec@lists.infradead.org,
 kasan-dev@googlegroups.com, Jason Gunthorpe <jgg@nvidia.com>
Subject: Re: [PATCH v2 00/16] expand mmap_prepare functionality, port more
 users
Message-Id: <20250910143845.7ecfed713e436ed532c93491@linux-foundation.org>
In-Reply-To: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
References: <cover.1757534913.git.lorenzo.stoakes@oracle.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=ERlNyzA+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 10 Sep 2025 21:21:55 +0100 Lorenzo Stoakes <lorenzo.stoakes@oracle.com> wrote:

> Since commit c84bf6dd2b83 ("mm: introduce new .mmap_prepare() file
> callback"), The f_op->mmap hook has been deprecated in favour of
> f_op->mmap_prepare.
> 
> This was introduced in order to make it possible for us to eventually
> eliminate the f_op->mmap hook which is highly problematic as it allows
> drivers and filesystems raw access to a VMA which is not yet correctly
> initialised.
> 
> This hook also introduced complexity for the memory mapping operation, as
> we must correctly unwind what we do should an error arises.
> 
> Overall this interface being so open has caused significant problems for
> us, including security issues, it is important for us to simply eliminate
> this as a source of problems.
> 
> Therefore this series continues what was established by extending the
> functionality further to permit more drivers and filesystems to use
> mmap_prepare.

Cool, I'll add this to mm-new but I'll suppress the usual emails.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250910143845.7ecfed713e436ed532c93491%40linux-foundation.org.
