Return-Path: <kasan-dev+bncBD4YBRE7WQBBB2ULYDCQMGQE2AZDARY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D205B3952C
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 09:31:56 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-3cca50781ddsf266358f8f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:31:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756366315; cv=pass;
        d=google.com; s=arc-20240605;
        b=MdyK7ULOwB312SeI82mt1ssZeTys08gF1cAl4FkaMTc+CdaNB6l6+Y53T7zy9zqkO1
         5v3eKiF6UFTmpD93cVIc8U16KCaKIAiGfV1scH86cyCjsteuGcQVKmwDfFnMwwSWyIkp
         YvHaAlMCH1MO1ZETzP+eSnzAhJi5LvA397T1MqMJrmFyisLSk5Wgs7rT2Q8J98fGwt1F
         rj7WVH7/WJcOuznUIGvaLCbqz3hMPnjdyCGsSDzI+qvPTyKhYH+m0ko2zzjWN/3S6Fmv
         PYdHlKa1dQfh2CEOuzIKPOy4EnjSceFaB1I0tMwums7fF7LGaSveTj4+1e6XpIoDPMOz
         2YwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature:dkim-signature;
        bh=a8GqKRbiC5eRApr+UHZJFGL54fYK1FcV5CyAdSlF0PU=;
        fh=2R/G0rKMqWnFPwhdh50bYwLvL9VNNuVitXNjmY091V8=;
        b=iUN/hJoGVc3wlRor3C3aRN0qbpigsm9byv/KJsEdeLqLue+FJj0C7L5akOU4XqcvaL
         e+Ao5BhONuQA76k5FhSGEedZD1Wf1B54kQf0JKxv62Sqb+N0dV+0TFU90m5RDOUECU6x
         meaXA3361NNaXabdqxmKfiXBvQKikc9ZaD6Kr4mxewoH6eMwIRZ34WHvVrAO3pnJDaVO
         Fk9htppuwFblD4fTYWqCD3KhXZLmvdk2gWF3ITidE9x5em8s+YK8hBDLWUuZ1XX+0uJ6
         MCvDng/5XG/bv9dJi/zN4xFV6RgBPI4xwV75MlOczpPdWXsVS8SyU9cHW3GIsVIuAD6T
         9JvQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="C/Frisq4";
       spf=pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756366315; x=1756971115; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=a8GqKRbiC5eRApr+UHZJFGL54fYK1FcV5CyAdSlF0PU=;
        b=TYOBZBAGbehV6+tKrEYbP38+v8L6CPRhyvHsia6OOScMSl86M9I5qei0zdLI67uz5W
         1AMff2IuQ+qIf6vCEQd90OjmnzEvak6fFrea2qH1jLTKIE0Z4Ut9KtvEpYP7QYE3PZJu
         Aiu5IRsKvJdpqoDm8SDdVH5JmYOXKIQJyiwA2lzC9D/MU2wgLqVe0iRDgT+3tCf57Nms
         XOYKyxro6+Clwj5sbjlPi9Iwe/m+NkXUTBpRKWuqjCMBthHj2XNJAAy2rAmWZXfOKztT
         eNFACxjIVx/IXLxo2xfcCtQpgsfAZ63AuOJKoBRxEq9OAPv2Owl2C9ixBWPXRD3Qv0Qw
         Dfog==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756366315; x=1756971115; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :from:to:cc:subject:date:message-id:reply-to;
        bh=a8GqKRbiC5eRApr+UHZJFGL54fYK1FcV5CyAdSlF0PU=;
        b=KFZHXqUvXQdJYNgjQ5R9qhLOt0tQisi9bJYcYKnrKr5de/VbtZCyKHKBZyzl0SxwfI
         Oxd45TJEROt70Qzn2JteUxiaeXR+XLoLxEILM1/fuXqqf/ywlF/Afu8hIHhM8cZotVyj
         xYB58c6oaU1+68XpZRjJsA784woU2AwX5Y1MVn/uwaCaGvbSGaaVt5ySiICLRtJyrYjB
         ObDlB4BVr4+noOz5ZiqHqv6ghA+fHG381v2ADT4WMpItCQV75YKbuzXLZ2V5LBx7guHS
         HGQ2BsWw2GzRLVPBPnV3Fd7mykxjNB9cpfPDq4j5DZao1nBmS9YVPHtyHgTx6NUY9hl2
         P3ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756366315; x=1756971115;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=a8GqKRbiC5eRApr+UHZJFGL54fYK1FcV5CyAdSlF0PU=;
        b=B7XaK6MfMqkqH5aU4GuNfO3hLHd1OtsPQQr4v+++bpSgK51cFZMjUOTOG0+j0vTUkr
         nSbu/h0jd+ZD4ouRqGXZE9Dr4QUeMU6wu1+9Uoel3fcwyZQQVdtr/pKPM1iujNUVRAxJ
         2nsCDCa6zfEAOYVAKjDSWTKErUBoNJ5Mptyijd2i5G8ELsWMMQONYAfMGhKB7dDneMj0
         KuKzi6MHYuvsz3+QnFjYUbGRCL81mntTq6VOt/7ywAi8CF4ju4vhwWFgiFIR3uX2oqOy
         2r607Y2CRrs6PzGqEglrPrG/1ruGQpROt5FzkmggHxZ1LaBpu/DKn1tlRny7MBadv3Vu
         LzfQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUwBH20TwU48A22jNd+4zVlXfB5uzCPRMlEuzjRChPRYq9Hq1fGtOQrym3GU2ZpSP7Q35jAQw==@lfdr.de
X-Gm-Message-State: AOJu0YzmKGHCbxIC3Oum6H0qgqjhnrW1NnOjrv/g68gTsTwq1OqfMDD3
	1mH2lURQ4i50K/+kco9nsQGua4btbg3rNArW9U1ZssdK3a4CQTbbFSyI
X-Google-Smtp-Source: AGHT+IF9HF+OEtHvnYFmn2B4GR0tQs4j8lj72iRoUEM5VBGeRAZJLgtg92XYxO+hdJGEHP5KRgsQeg==
X-Received: by 2002:a5d:64ea:0:b0:3ce:663a:c91f with SMTP id ffacd0b85a97d-3ce663accb0mr370468f8f.42.1756366315249;
        Thu, 28 Aug 2025 00:31:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfvTwgje8qHWlg9eJmjs4t/jqpaP5Luoy9+IM4YMLyGhA==
Received: by 2002:a05:6000:400d:b0:3b7:8ddc:8784 with SMTP id
 ffacd0b85a97d-3cde38fec52ls204582f8f.1.-pod-prod-03-eu; Thu, 28 Aug 2025
 00:31:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVSECk5FCaRS5rtN2LTh5gFEXan6b8AkGCgFWsYUmsZQ/ToVHq7/V0iNWFvqWk4xnqjS6IFGNHqbII=@googlegroups.com
X-Received: by 2002:a05:6000:2709:b0:3cd:5815:68d4 with SMTP id ffacd0b85a97d-3cd58156b71mr1772492f8f.57.1756366312080;
        Thu, 28 Aug 2025 00:31:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756366312; cv=none;
        d=google.com; s=arc-20240605;
        b=SN9qrdgjWZLmKrTL7EQ5xYP+LK47XQEcos8yVB4G3k4srJs3tL2QPItOQvuPOhEKec
         e1irSGTNcHIQQrAcc+ssGoTrmFyQGl7CLfVhPXGJA2Ingf3sJrlroMSr09iHjT4MAncB
         INUqpFMSW1888859EHUqpMVv2ZtKwHPSF6ZOFzCYjw3zEud7Mj4Q6u1fDnf6nmw3bfSB
         29a0oOmVaU0KUmN1tr//M3QgaLk2OP/a4H0ONoRPqiMaMxtQZ+yByRssgzCN5y623k8w
         BQnQBvGF6R7RbGSYcqyl+05CT0nZ8DJNJvsnFJ9MVb3XeSdVkiEtghOUqXFv46Mq5cKQ
         /98Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=EuV0vIwmYzbGp0NvCAEdvEWsqc4i4ounAUIZgXtsn78=;
        fh=zaKSDusU9hfmUTacOFrnVE1zhFoCtF8j3IW9FOnu4cQ=;
        b=M8xacZQ41cQQ1Hj0WHb0ZDtSHjUABrK0aUw6ss9tN0Z+h2o3XYkAely+XeCTXMH4GD
         7Uryodv+i2WISYwK/W0lcGa8rvzSkkREUIT813H8TyNsttL6dKpS8eD47jLQIHjRMqXH
         3sFe+L9cSt+WOY/OjpRYjk4Nq7kOtNXeZ6zrtvHPFr+k3mVkdnvt/BRmQGfuwN3I8cqh
         SG+Zc0PI+H4AnMHyw8jtPHg9YWVS3p3UQ0m/9Rg7kLhFaLu9t4Luf14p+hO5YoGr94Xo
         QLTT+IZHaNAXR4ZfpV/8uiqH43Mszq0C0L8jyXKlgqGTcsu+oQarTVLV9DC2EVDDKG5i
         Amsw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="C/Frisq4";
       spf=pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45b6f072618si686465e9.0.2025.08.28.00.31.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Aug 2025 00:31:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id ffacd0b85a97d-3c380aa1ad0so286200f8f.3
        for <kasan-dev@googlegroups.com>; Thu, 28 Aug 2025 00:31:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV17u2snp9GLjjf09WRLILGecUHinccqHAP7hxD02Y1YL7G5hunZnXMrrR72fbtZw2awJ4ZWdfZc3Q=@googlegroups.com
X-Gm-Gg: ASbGncsQjrt26rEO/HKRwoNnCptACDB4vN9/eWu4ipX0IBP52zKqJQ0Eqg6W3A4xg4x
	GkIRiqbNlEicnOhbnuPfBMsul1aRJ4r9Kqt3o8x12Ox1vVyePkeNRkhybx4882/Il+jVTmSlMsx
	SK9m1EUwjKkVvX0bTA+y/xAylTbQ8Gu047u8RcOEYMEh2eVwK8QmbGV3kwR9DiTljL3ETjM4Jqn
	h/7zUNLwM59PIBm/Z4/2Fga7mzgxuZHcf6uhxCNCP6eKvKawakDVVNXx1wZ9GqEx2wyt/GwC9zX
	Tl2zoia/70NwQWXrCXqOiBhNlkxiL9/Xj6snIHBNuiR7Cqd5fhb4pd2i5HWKuEs1/LWYTh52CAy
	LcSunTqXNiFS3mELyoS4I3WgFwzcYWFqfa3qp
X-Received: by 2002:a05:6000:2891:b0:3cd:96bb:b948 with SMTP id ffacd0b85a97d-3cd96bbc28fmr1837267f8f.47.1756366311260;
        Thu, 28 Aug 2025 00:31:51 -0700 (PDT)
Received: from localhost ([185.92.221.13])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3c9c9324dc9sm14883755f8f.3.2025.08.28.00.31.50
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 28 Aug 2025 00:31:50 -0700 (PDT)
Date: Thu, 28 Aug 2025 07:31:50 +0000
From: Wei Yang <richard.weiyang@gmail.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Zi Yan <ziy@nvidia.com>,
	SeongJae Park <sj@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
	io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>,
	Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>,
	John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
	kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
	linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
	linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
	linux-mmc@vger.kernel.org, linux-mm@kvack.org,
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Marco Elver <elver@google.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
	Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
	Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com, x86@kernel.org
Subject: Re: [PATCH v1 06/36] mm/page_alloc: reject unreasonable
 folio/compound page sizes in alloc_contig_range_noprof()
Message-ID: <20250828073150.jyafkufvkjfqwp3f@master>
Reply-To: Wei Yang <richard.weiyang@gmail.com>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-7-david@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-7-david@redhat.com>
User-Agent: NeoMutt/20170113 (1.7.2)
X-Original-Sender: richard.weiyang@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="C/Frisq4";       spf=pass
 (google.com: domain of richard.weiyang@gmail.com designates
 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Thu, Aug 28, 2025 at 12:01:10AM +0200, David Hildenbrand wrote:
>Let's reject them early, which in turn makes folio_alloc_gigantic() reject
>them properly.
>
>To avoid converting from order to nr_pages, let's just add MAX_FOLIO_ORDER
>and calculate MAX_FOLIO_NR_PAGES based on that.
>
>Reviewed-by: Zi Yan <ziy@nvidia.com>
>Acked-by: SeongJae Park <sj@kernel.org>
>Signed-off-by: David Hildenbrand <david@redhat.com>

Reviewed-by: Wei Yang <richard.weiyang@gmail.com>

-- 
Wei Yang
Help you, Help me

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250828073150.jyafkufvkjfqwp3f%40master.
