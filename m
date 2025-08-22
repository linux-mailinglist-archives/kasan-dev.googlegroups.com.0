Return-Path: <kasan-dev+bncBCX7HX6VTEARBFFKUHCQMGQE5YHRD5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 756A4B31659
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 13:31:34 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-55ce50946e1sf1023243e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 04:31:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755862294; cv=pass;
        d=google.com; s=arc-20240605;
        b=BczjlNMytoPgnimvw7e1ZD5JzHJELnqm+RcWRYMO8ix9jCKiDVAJn8mNlhrkBZPdUd
         Bm2CaVsxF8SpnRbLi4uoLRI+9FAEKbx02vIgFX8CyOb9nHsvyZ7VuFkB5pBH4x5Bssnd
         ZzvDubdEL3L7jKFEOEE7wGjb10xIYyV5V9PSCCV+umEIq1dJNVLB1zlitKAg2ri5G0Vq
         6BAUfccb2TNWej3C6qObVasYQwZvNeI/UgoxHImVfHQyo5bPZ5q638v+cqC9cyrRTgwg
         zsjM7xHz3PCij3b4pCeCmRKRRYVSziOjvZ345/p/eO2AmMupm0gnw7K66icJBRG0+YQW
         y1kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=en6GwNNkfRAZKIIgXAjsgIKkWAux1VzV53repG5SJ2c=;
        fh=ZttOUc7SibZUoVpZ6zSBcT6sL2vbPdiuTbpJhGXssyE=;
        b=G6RAbJ9CLi65NvgZazIWW0PTS0d7px00CuwXTMfqL6Rc9iSoyllY9lGwXUwfjiWX3s
         VqR+ob9KAw0wLQlMnbu5guH2i4vpz9519J/AxqS2MZRm1YVs2aQzQeRUrp4JEecBt/V5
         dYHP2p7B+CKc3FI4pK3wfBF9LOeAEjdXE6WvymtXSEvXgc0KRpMiESBPoZVvJJ/ms+kx
         WkrByuCHG5salaGaFSDqph/uYDIqA6ZjhABXTcGq54Zml+AsajaDdTztaCoZU5x80kq0
         FpLA5DVKuOQefqRMz8NDKZliXqMKteiVQq6d+RRf7tzoc0tOaRIYlZqoq+X94DKvrkVY
         wW/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Pk6uGdpT;
       spf=pass (google.com: domain of asml.silence@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=asml.silence@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755862294; x=1756467094; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=en6GwNNkfRAZKIIgXAjsgIKkWAux1VzV53repG5SJ2c=;
        b=Jwj7bwiTtVfHJjbYEQyPKWi/HhpRF7oWMRkjMIIzOrL9064mUssO4YzIPK0h4ynumC
         SpmdBwyujm34iEkHYBUtBR6PTw6uPbOXrG3uoIZWLdpoJeWtSW4d4IqM1orfKpFVBIAD
         8WOd/bx/SUaXNopRw/FJP9t9+aSbl45c0Blpcvbi3M3yNs36xSZn5eWgZh9f9wY3BfTq
         H8DXiYv+qSs+bX6jZIvdhpY9k9vdwYJ+vIrc5dBdlpvUyJfYnn/MCMth/xifiV/4XRz1
         7NCCxdnxcqn4IGAvpPsLspgC/7toe04RmwqMSFDGquiA+fDnps2kbFr4yXv/GlGlgDJ7
         Sc6A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755862294; x=1756467094; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=en6GwNNkfRAZKIIgXAjsgIKkWAux1VzV53repG5SJ2c=;
        b=erBk72oN4lYxdlDjhaodl0j0OyHgWHm3PG9BsSIBTfyJsI6AxVG8Uor0KzoeZ1SSBo
         P5oEOd4BQlQEO+SIBOjNxcJu9/VkPrdPUwuA7/lBXNgZxHJEP1FWwfZ8F0bSpY9MpgdE
         WNgvNMULQb9KdbBJyCEzsicP6EeRubmYPkkMk4rVxhMczfqSUXBudaux0YcWm4DIj0J/
         2upnd2l4X6puc8CZ7vQ8EvwIj9qtpebHKaixn0gs510oDpn1HIfnhTjf2rznwmPm5GO4
         kqh0zKq3tV2U6rGcxcpH3y1OiAu9HTVdRi2xENOQI5buoJeJxC9nskEThTiOg1brwGn4
         yaqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755862294; x=1756467094;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=en6GwNNkfRAZKIIgXAjsgIKkWAux1VzV53repG5SJ2c=;
        b=ZqUfzdrnm+yLorGzaQBReNYrGcOnp4ZAaYDFvydoujWhfF02hWJjFQU83vuLkajPo0
         BV7/px6zuC37SOI7+9R0/4/2K1AvejQ/is9pCDqtkeHbON+C7bncfegIM/Z6TdmdQzGr
         Y/IUWDw6K44izlI+dWuHhmzA3zUvIrlsRHHA1Y9Th5BVewXYVWcl30Yk2M/uVVopXm9X
         sJ0zTIFSvxoK2hOfS2Ci2SwaA52Xmcpk0bxIASvg67kyqsbBnMXZunWiY3DXCZiPySyH
         zfle17y1zn32gy4KIDvj+WwWruVzYuXmovalvKPO7B/xoLI6oCjjK4UUPCeDxCmL6Ozg
         5Byw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVCPNd0/MdbMt5m3pIzMd/jee6/SeR8y5YqPUfXXDz4qHNm6nGy3hT5KkCiOctKax23leO65Q==@lfdr.de
X-Gm-Message-State: AOJu0YyAIlqfclJ3JLBP0+p/A65FLBZTI/dJuDzYabjLC6eo6xcPSMny
	DDoFT9A03dLP4s+xzdYrtkpzGDwTA+3TNy/ucZX/iC/LeUQnzV3Ebqim
X-Google-Smtp-Source: AGHT+IETy7sqDuueWaxl3MaIiDrfA2X7cCrcrNTYmlgJlhixX09XQySxxwtNGbe+ZPkTVQw3ZjSpNA==
X-Received: by 2002:a05:6512:244f:b0:55b:7fb2:1ce3 with SMTP id 2adb3069b0e04-55f0c6b507emr877449e87.19.1755862293365;
        Fri, 22 Aug 2025 04:31:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeio8IVcAFB2KFPsb6fxf9XgZg/6ogWKrhunoq47bC7bg==
Received: by 2002:a05:6512:6391:b0:55b:9cce:ecc9 with SMTP id
 2adb3069b0e04-55e0c849e7bls334715e87.1.-pod-prod-08-eu; Fri, 22 Aug 2025
 04:31:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVDK79NaXdG/yWnBwhRF6n16meAnE4Ns2lsJ4aA0RZGqcBMGeyUbGP3uo9UWTuEvlGwSeos84f3uzo=@googlegroups.com
X-Received: by 2002:a05:6512:b26:b0:55b:8c5e:8374 with SMTP id 2adb3069b0e04-55f0c68cb8emr804707e87.2.1755862289136;
        Fri, 22 Aug 2025 04:31:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755862289; cv=none;
        d=google.com; s=arc-20240605;
        b=U+A4Ll3Hd+wRnTa0kubJnSXjnbcc8v97c3Bi83/uT5B2qnoeuQblvu3khOXyvXxs8A
         +G4WP3WhT3py8R43Z35PQTX7eYkQjliv314v8dEHLxKzYgyDbkAqneSud3C6ecJaEnoU
         DruAglEH8qMPvKPHZ0/qVknuLoA+tvf8QlSlweJ9yS9XEaAsucOFJbesgFVEcWTf1CsS
         dYErOrb8NFQJRO7P55pgQGBLw73KuCYLl/OIOQJxcvDvImI/B9n9zBkA/W/fRYwsyEzD
         KczNV/rcCMMJso6QzBG4Y/n6IAYn10K9DSfOa4Sw+GTDJCa/dSCaxTeB2xlEt9qGbAVq
         yQ9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=SfbHPH5Jjp8Rpz5+ZFUkvP8crb1ywqdy8VPh1hjPgaM=;
        fh=mfMOODDi+kXUntmMGGfOZ9ff4B6jdPP1srFTmXyanu0=;
        b=BjagKTVal2sFqzTyi2ZkP7DAA2AbXu7KSXG54+hMWqK1K7nmqxC+mgV9jRAy0oymVk
         cxke22x0Yb4pBYKUWw+h2zBvknS6DwDuRtlqjlmZxByyQDJmOBKtD+wYEu0YEiJBMg/3
         eOX+CzS/yGBL6v3wZYIekjTRFObPsCmiv8wZFk58VXgdy51Aij01CzSqnliuyzPVptXb
         VqriLlr8T5DJ6kgDB2I9JEfffz55QShg7pcSoHWSFot718pKKu5IPRFlQ3qtvWzja9Ud
         fLf7oAzICTbuV6zXLRXDu7YGUeO9KgqtoUIIUCOj/vMrpXCrHO13UTB7dB3jPVZxmuNP
         5NVg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Pk6uGdpT;
       spf=pass (google.com: domain of asml.silence@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=asml.silence@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55cef43e173si416802e87.4.2025.08.22.04.31.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Aug 2025 04:31:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of asml.silence@gmail.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id 5b1f17b1804b1-45b4d89217aso9434375e9.2
        for <kasan-dev@googlegroups.com>; Fri, 22 Aug 2025 04:31:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUuFm7m1GTugZqP1zshJvORd0DFJAnFMAcIYvScP2unnQzRLkjIaEMWxOMdmvjcpq+1lU70F5zck0o=@googlegroups.com
X-Gm-Gg: ASbGncvwgS7mK+YuzASpciHnxz2DbQ456CwMazguwZW+I/bXucmpmR+rLIegN0Kac17
	mK/Dxy0DqPctgMAibzXsQkVmlBOQqiUQFBC359oOdYY2IqM2HqrX8U54k2pGGIhznYhEq0kyp0r
	N5QZ925Tl9XOObT+JD4vQBv47MnrlpjWfpv9tB+1WpCmy6r5qiWK7RIrIp3r45Gly1oWmHyPbeI
	C/k+l5wNfVWEJU2veFuUg/mkhONnslmHhg1a+0G0giXaEan/rE/i7ZF+alko01vx7oFdYIXzOwV
	qByF+WD/AGc7SH+xtupcTlGX7qrhhh1FUlW2c82CE8hlyGS0Rq99tZQ0zea2Ac2kJ8osMxxdbIj
	H68Xijlg8bnrFs+NngUTPcB6BrYmWEA4vbvkcHzloUaNHIlcuU+uidlE=
X-Received: by 2002:a05:600c:4747:b0:459:e094:92cb with SMTP id 5b1f17b1804b1-45b517ad81bmr24844685e9.12.1755862287996;
        Fri, 22 Aug 2025 04:31:27 -0700 (PDT)
Received: from ?IPV6:2620:10d:c096:325:77fd:1068:74c8:af87? ([2620:10d:c092:600::1:1b93])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b50e4241dsm35921185e9.24.2025.08.22.04.31.25
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Aug 2025 04:31:27 -0700 (PDT)
Message-ID: <b5b08ad3-d8cd-45ff-9767-7cf1b22b5e03@gmail.com>
Date: Fri, 22 Aug 2025 12:32:58 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 18/35] io_uring/zcrx: remove "struct io_copy_cache"
 and one nth_page() usage
To: David Hildenbrand <david@redhat.com>, linux-kernel@vger.kernel.org
Cc: Jens Axboe <axboe@kernel.dk>, Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Johannes Weiner <hannes@cmpxchg.org>,
 John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
 kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, linux-arm-kernel@axis.com,
 linux-arm-kernel@lists.infradead.org, linux-crypto@vger.kernel.org,
 linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-scsi@vger.kernel.org, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Marco Elver <elver@google.com>, Marek Szyprowski <m.szyprowski@samsung.com>,
 Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
 Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
 Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
 Robin Murphy <robin.murphy@arm.com>, Suren Baghdasaryan <surenb@google.com>,
 Tejun Heo <tj@kernel.org>, virtualization@lists.linux.dev,
 Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org,
 Zi Yan <ziy@nvidia.com>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-19-david@redhat.com>
Content-Language: en-US
From: Pavel Begunkov <asml.silence@gmail.com>
In-Reply-To: <20250821200701.1329277-19-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: asml.Silence@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Pk6uGdpT;       spf=pass
 (google.com: domain of asml.silence@gmail.com designates 2a00:1450:4864:20::334
 as permitted sender) smtp.mailfrom=asml.silence@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On 8/21/25 21:06, David Hildenbrand wrote:
> We always provide a single dst page, it's unclear why the io_copy_cache
> complexity is required.

Because it'll need to be pulled outside the loop to reuse the page for
multiple copies, i.e. packing multiple fragments of the same skb into
it. Not finished, and currently it's wasting memory.

Why not do as below? Pages there never cross boundaries of their folios.

Do you want it to be taken into the io_uring tree?

diff --git a/io_uring/zcrx.c b/io_uring/zcrx.c
index e5ff49f3425e..18c12f4b56b6 100644
--- a/io_uring/zcrx.c
+++ b/io_uring/zcrx.c
@@ -975,9 +975,9 @@ static ssize_t io_copy_page(struct io_copy_cache *cc, struct page *src_page,
  
  		if (folio_test_partial_kmap(page_folio(dst_page)) ||
  		    folio_test_partial_kmap(page_folio(src_page))) {
-			dst_page = nth_page(dst_page, dst_offset / PAGE_SIZE);
+			dst_page += dst_offset / PAGE_SIZE;
  			dst_offset = offset_in_page(dst_offset);
-			src_page = nth_page(src_page, src_offset / PAGE_SIZE);
+			src_page += src_offset / PAGE_SIZE;
  			src_offset = offset_in_page(src_offset);
  			n = min(PAGE_SIZE - src_offset, PAGE_SIZE - dst_offset);
  			n = min(n, len);

-- 
Pavel Begunkov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b5b08ad3-d8cd-45ff-9767-7cf1b22b5e03%40gmail.com.
