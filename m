Return-Path: <kasan-dev+bncBCC4R3XF44KBBZ6HULCQMGQE5JTKTQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E149B32106
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 19:07:53 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-76e6e71f7c6sf2611497b3a.0
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 10:07:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755882472; cv=pass;
        d=google.com; s=arc-20240605;
        b=UY7GgYwVGUhDzWB8PmwHV+cyQB74eWaRf4wUosyga2xjviiNycTAW4M25V2UsQqRg3
         vMEgK3+jjZFAG+CSDwXhRiaOuKRJtKLZ/56x87m/fVWPQ6yZHun8Wqt69/9g8MwQOsaX
         2yHWvdVdyNR19QTBpPhKuQ1K45nE6IT6pq2BrlAX8W5RRS9Ku+HpXVw+vUted0g+C1sC
         QAOs5c+uh9bDBbQ9sLlZfai2XywVIXslMtIRxc787wphB/bJmXNaN/12V7Luj3K3k0CZ
         1kjn/b5lrIQ/mOf89FG2zrcqpGBkxBKhgKz9lnX7/dDsJplaH/wxgB6EYArk3xMSrdO4
         8vUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=3SiRxX1O4fSHDCH0xFXPZ607G+5riMy9vSgxNbfuppo=;
        fh=QdfypGHuVf7RFvMT9ytjl5SwhtWVg8THnDucEqgk51w=;
        b=c6VjutifDwYFnLjG8pE48eag3d8QERsaQWlFsn8Ch4/OmLNzWn+k+G71J3xZ6cDt0q
         GBoBjpJhJq8+rS8bQG9OV9FBYoib49QdAHcA6pnMb7joGKqnSSV8l0KwWCN5AuGgkVIR
         AJxpMUYPuDsBSuXmhJbp9rx/r33L+tdfCqQTkc6UV6k4Gp6sMafQ+1LHU/HuNxT16b4U
         TR221rJLbOsS8x+deCPsSPB4T84xKfeN/+aKcRias+1fRvib1zO1O2+9/0cDWgrp1XJU
         VqG/NUaP8lAsV9r+YChor3uuQMAgtGRigFKAvCm7OK6I0DJxr8p4OZ2IzaD3BsTclCvH
         y6nA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fSplAPAb;
       spf=pass (google.com: domain of sj@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755882472; x=1756487272; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=3SiRxX1O4fSHDCH0xFXPZ607G+5riMy9vSgxNbfuppo=;
        b=ZrgaBKEd7TQSsQx7I/wg4DVWgg8HcVsoprIl7otVijqQgKhvr7dK/gnKApnXo5YlkW
         aFG3/yc24ovM/XKiVYdetOnyRtnxRvIZYBq2FHf5OMTGu3eXufTt21INpbH94TCDw37n
         yc1/H2ixG5/swEakTqO4e1lP+YK9Vf4rXXubafTUq1dfhtBwIVnQRAQw/VR0bIEstDky
         nFfA//sQVFNMHfu0EO8C2QmUsy18ICwdrXpPAgJKK/WsKJn8qXHOiPtqz22zTZNf1x5o
         qhqcbRFYMeX8ADXPMZySKdTrheUzvWbRsWOeHfSDAKg0tv4zzru2PCFiOefYvFmOfSJK
         CxZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755882472; x=1756487272;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3SiRxX1O4fSHDCH0xFXPZ607G+5riMy9vSgxNbfuppo=;
        b=HTqC4gJwF7CxDuTlk3mIVV6cLx/iSguVPaurRdFLwC3fwJY1UV9PSb7n8vGIQeFHlK
         1YL/xSSgiiig1oa10k2OtC2FRJSbgr87USiCtVOOBqyNN5TOzKY1pJtPBPyGBOP6xfD7
         inxqToxE24e5dhd3fQcBu7ybrvRQOAPTzOx00k+jfoOWiY1+bKiqkXo2yQbaUVx+7h0X
         o+8LqQSDlrvgONWe7aQgeUUma7KjEOouGR+GIc56mgGm1DObkCt5grfaW+SqSGDUAcqI
         8oroOq3tlItUFtE2R9SQbJlmZW96pe9kpAbnXQnXGd5pKsHCYLlidF4GYsHl1qmvzDL0
         duXQ==
X-Forwarded-Encrypted: i=2; AJvYcCWM05I6TUoFhABoQg3kbm1Vw+9QqjvOts2SbCuu36Rh4dS5stwezm2v36N1TydPN0PKRUZf7Q==@lfdr.de
X-Gm-Message-State: AOJu0Ywsp9W8dWABFTRnIbTdh9K1xYGx6v9rLCojklFNE5LFZwkUjdtX
	hvCFMwzsmhaITKh5WFspUOT9BzgAe0TEIqFlzrzVREUVyKJS733ZWtb8
X-Google-Smtp-Source: AGHT+IE4/9k8YSyb5dgOgCAgXaNS/dd7+TKWv582eqKEW1PPNUcla/1pH53KrbB01AdDFnr+2rshHQ==
X-Received: by 2002:a05:6a20:4325:b0:243:755:58b5 with SMTP id adf61e73a8af0-24340d920b2mr5889809637.54.1755882471657;
        Fri, 22 Aug 2025 10:07:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZenlGW95mzrtrFRL6MAXsKMOM0xUBK/NFsXg30RDk1puQ==
Received: by 2002:a17:90b:2292:b0:313:9f92:9c2e with SMTP id
 98e67ed59e1d1-324eb8538f0ls1865216a91.2.-pod-prod-01-us; Fri, 22 Aug 2025
 10:07:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWtkujTiOTaCSKsYu9cLKooOf+MisOoajsnHQyA7cAkAdZRXjmAWi9ihcNWM8P3VCv7lvTLJoBvQIQ=@googlegroups.com
X-Received: by 2002:a17:90a:d2ce:b0:31e:d9f0:9b92 with SMTP id 98e67ed59e1d1-32515ef2d98mr5660183a91.14.1755882470175;
        Fri, 22 Aug 2025 10:07:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755882470; cv=none;
        d=google.com; s=arc-20240605;
        b=L3XHAv4Ykd2wf0fIvv5e99N3dNRSnIoGHkjr71mCdgmOL6yklB0QMMcEjq0o0HLqn7
         JlZ/TxAq4LKmy1W/a2loxDawtw1Wyx6redx7gzfl7u2DXjiBrD+CTB5ACsQNtEaqeqeG
         GAy2miPnLbleaYOczk1+XRkVR8le+/AX54KN3U0F9OXik/pFI1vjJXmparf/tYicfZoa
         NWAC8DD0aE5nhBuf/Q3aCGyXgOxSaFzEPMqDHHy6qgWHHalg0X/fRF3/5T9u6mHzadZ7
         IripSrXtk2vblpZWiRaac6GLgrloTazIWdzwqVzN3IpxFeYE6YxWwYcPQ/WXQMELSN8O
         1ADA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=QFfb/Sn4tzsBL8+lFf8/4nSkR7hbOY5oXUR5CVb78zM=;
        fh=8jFVrPivn9/kDacsJ7nevehv3FZKrA85eOV9G4jZP3M=;
        b=ChwOiyXV5NYQnrrwLD2XO4Od/IjuxWBJjleinpup2s6NR8c85QxNmN4LVGVV+K5wmN
         Xj4aVywlBm/gxHpPnQBs5xQY4/WQaRZaMQx378F+OwdCB9kS/9zjqSq+iXX9hOmlJ+Cy
         bC7AN7eeYM2cbso0fV0pKqTW7MG4+/59qilCFg+TToQ8qosAut3XKobdkIacbMmDr8F4
         HdLX+0dGAZyVUq3YDosT6+bKWfwSvPpvir6d8RdVeW17HFBoz0hqmq/sCB4NasBn1xuT
         cAEIyF+trdZ4G8snm10Sbi6DGaQ3mUAUuov/OIIUqpad7W2+Gex+6CyRPnLV01MuEova
         YZHQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fSplAPAb;
       spf=pass (google.com: domain of sj@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-324f80bf225si222865a91.1.2025.08.22.10.07.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Aug 2025 10:07:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of sj@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 2DE1360203;
	Fri, 22 Aug 2025 17:07:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id AD1D1C4CEF4;
	Fri, 22 Aug 2025 17:07:48 +0000 (UTC)
From: "'SeongJae Park' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: SeongJae Park <sj@kernel.org>,
	linux-kernel@vger.kernel.org,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>,
	Dennis Zhou <dennis@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org,
	iommu@lists.linux.dev,
	io-uring@vger.kernel.org,
	Jason Gunthorpe <jgg@nvidia.com>,
	Jens Axboe <axboe@kernel.dk>,
	Johannes Weiner <hannes@cmpxchg.org>,
	John Hubbard <jhubbard@nvidia.com>,
	kasan-dev@googlegroups.com,
	kvm@vger.kernel.org,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-arm-kernel@axis.com,
	linux-arm-kernel@lists.infradead.org,
	linux-crypto@vger.kernel.org,
	linux-ide@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	linux-mips@vger.kernel.org,
	linux-mmc@vger.kernel.org,
	linux-mm@kvack.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Marco Elver <elver@google.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>,
	Mike Rapoport <rppt@kernel.org>,
	Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org,
	Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev,
	Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com,
	x86@kernel.org,
	Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH RFC 06/35] mm/page_alloc: reject unreasonable folio/compound page sizes in alloc_contig_range_noprof()
Date: Fri, 22 Aug 2025 10:07:46 -0700
Message-Id: <20250822170746.53309-1-sj@kernel.org>
X-Mailer: git-send-email 2.39.5
In-Reply-To: <20250821200701.1329277-7-david@redhat.com>
References: 
MIME-Version: 1.0
X-Original-Sender: sj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fSplAPAb;       spf=pass
 (google.com: domain of sj@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=sj@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: SeongJae Park <sj@kernel.org>
Reply-To: SeongJae Park <sj@kernel.org>
Content-Type: text/plain; charset="UTF-8"
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

On Thu, 21 Aug 2025 22:06:32 +0200 David Hildenbrand <david@redhat.com> wrote:

> Let's reject them early,

I like early failures. :)

> which in turn makes folio_alloc_gigantic() reject
> them properly.
> 
> To avoid converting from order to nr_pages, let's just add MAX_FOLIO_ORDER
> and calculate MAX_FOLIO_NR_PAGES based on that.
> 
> Signed-off-by: David Hildenbrand <david@redhat.com>

Acked-by: SeongJae Park <sj@kernel.org>


Thanks,
SJ

[...]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250822170746.53309-1-sj%40kernel.org.
