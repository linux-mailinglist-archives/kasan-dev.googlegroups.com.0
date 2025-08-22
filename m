Return-Path: <kasan-dev+bncBCC4R3XF44KBBY6IULCQMGQEJ7FVSNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id E9C98B32129
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 19:09:57 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-76e2e5fde8fsf2320285b3a.0
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 10:09:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755882596; cv=pass;
        d=google.com; s=arc-20240605;
        b=QXAc+Qn9oXOHV2YPfnP1fHyiuSD3Ox4fkJpWttZInYeYsB5HDeKH32d9qHQmyQwJf0
         LM334Hi/4PAH2fi+as0upJDkvvoFKR7+++R1ccK1DaXPwfxInnYud5/3oyZYmx+yB+N9
         Rhy2qSpFa1PkAqj1dK2Rq6qNYsAH8aK5GggfR4nXDPr4G74cnnu6wmEzgqnWj7omcMZ9
         +CLaMEqkMe9/AXHOBVQK5iLYN3Ha8oaOtPz1n0r9/vX48PFyZHzrHDGSlBHfhP2AO795
         4DhxkEDvaHR8sjcv5vsP0Exkp0p+ofYKqRgCCNLbGwHgicNyvQSiNOIn4/YrWpAsaPB1
         QPdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=nQy/17evdWZ7FmQJXEhcnz7wZqqM+ULPSDUWOEW+7R0=;
        fh=IDQyfS9/59zfUIUsQjS0fX7gQ3m9UVPYQ/PtL0oS+x4=;
        b=E2RmPuIaeyidtztGx07Bko+5D5fLX+Mbr9hYuTACVQmrInFg2HW6rOvtIF6NsKsea6
         Le5/Agj0xCetwtGtoJOkgfHSVIk5jckJt7ZUHwC5bAK68KkXmnTLe3mAm0B7SQY/TSd8
         nEr7nT0mSzApvl12t+F8XdtG4ckROyaOeP2QZ2S/Kqz5N85IWDxsNsGLiKxC7B3DBRuN
         kfT3Z6iU6YS5YjLhUTa1l9Hisk6Y6bkgshuary2SScn3w6hqSg1TaOuYgEN+AXS9StaI
         HIbeBMHi+6i6QXqyG82HWMWvu5rtcNy5WX8GN3X+mA6pJc4dvwu7dU40Axi4FAtIjM0q
         UFyw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DmWBU4Vz;
       spf=pass (google.com: domain of sj@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755882596; x=1756487396; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=nQy/17evdWZ7FmQJXEhcnz7wZqqM+ULPSDUWOEW+7R0=;
        b=pFsINeEQLnhTutWgYeTgL1/b3OoUOlKeXh0xoArxQvmuYekwEdW3YC0UA6uUvv2RhK
         QfDLgr4Yal79+WbUFo/7VmVFmKRBpJQ9xzN6qIO0JXCGVtfEHXtyOGumyrjoSavfc1kI
         IX77YwQefIz7Won8aip38n8WkcpacfuDmF0gJfGRhlTHOKCiyL4xa1pJrJGCmL2BUWIO
         VJwdg02e8kPgXx1Jno+k2s48MCZkHlfwcOIKvMwZZw9zo9WPLJ8RV9FgLPqBJXShybM4
         v5vJ+fUOe5+4zxx3Pp7xN2Mi+MICLMwSp8bSjebCc2r223PuMm+Ji/1GDND5JIcA+Mqv
         3d5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755882596; x=1756487396;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nQy/17evdWZ7FmQJXEhcnz7wZqqM+ULPSDUWOEW+7R0=;
        b=lZyotf6v/AkjuMQV5Mr48c5q8n4rV2UVFjljEjsw2V+1tb4a4mvu5w33BiQrQ5Dwl0
         6cEcvZC0u39QjgTzIBAV0yfuWCbMp1NJUL6q9HKCynW1vvfYpyY+N89uDfuYdiKIsy/o
         WNWogjcRjwsWyKRDJ+Kltg9AQD9OvVQqfe8jmdugMxsGO+EKOEkaD/HMvv1WoE0e1kGo
         dVQMDE2J/uuOwd2p6DcsQUMWKyHikjUzxK1TFd89N2MM7y8A9qcmwSyE/6vbWWkQ0A2B
         nw8cbhYFIOMfWcr2M2ASF93TqjNMF+RS/Dl+GcZFdxIeHwHj7Wg8YvWFJ2n82+2YS7ND
         tDhA==
X-Forwarded-Encrypted: i=2; AJvYcCXL3AwfyrSiHZ2CuOlxOcJZ6XCAhGA4qmdTa0HmAKLKu3ljbZZ2R586oSXueqNCktw7r8Uf1g==@lfdr.de
X-Gm-Message-State: AOJu0YyLW2pofHQtsJs2qK9BArIcfQ3u5v8PRsPPm7cbC+Rrr5xvv+rQ
	DyK9u+D8aoOqBaqf6EjoCIcgrc3YHohGDf9DM3YhmINPmr3gbDPfZ/TG
X-Google-Smtp-Source: AGHT+IGNWfmiyWxhFBJBb2uX8l1uSHu3J2No7leBW71OIobg/51j8vCeN8+vF98Y78+Z8vY2YlzwRw==
X-Received: by 2002:a05:6a00:3cd3:b0:76e:3d16:6e7b with SMTP id d2e1a72fcca58-7702f9ede7bmr5295412b3a.8.1755882595769;
        Fri, 22 Aug 2025 10:09:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfPDOwuZHlI8vku5f9Ol6FjT+iXnoDkmRhAI8S3PEy2Ug==
Received: by 2002:a05:6a00:301c:b0:742:c6df:df1d with SMTP id
 d2e1a72fcca58-76ea02a0804ls2299382b3a.2.-pod-prod-05-us; Fri, 22 Aug 2025
 10:09:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW4Thw7cQaYqqi1HkjG3UVm6mm87ZQ2U8Q7xlhDev8i3gRVZSFA5rbamJfakZVfMo33SSKzLMJkuUA=@googlegroups.com
X-Received: by 2002:a05:6a00:1acd:b0:75f:914e:1972 with SMTP id d2e1a72fcca58-7702fac616dmr5965473b3a.17.1755882594483;
        Fri, 22 Aug 2025 10:09:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755882594; cv=none;
        d=google.com; s=arc-20240605;
        b=R/AiDx2ogzPfMWqLvJ2D1Bc+Fh481sPppQy3Qvwaux2CUMks7IIb3qQcswszzG78gV
         ZnNHUfUtvy3ibGGQmMfa9xM3izb7MN13plVybSVEU43hGMqUVZtN6KKf9mXDhc26sQqa
         MeUdmr0VqeJhjdGhjGbRYtSLDzFt5oCvTi+sRCI8WzASYlpyB+W41CRIgPK7AANRzH5a
         2QzVvj3D7/XbT9HKxX1neA5xk/EwU210tKhh+Z7ESUxGB3m5Te4N9NFA0RhwxmtHEh2E
         VZugj21CcvfEviJBhtKRmrMUEOyA2aNIot4RFA8G7dyf8gewrzhhF/6aB3SWcbllzoWr
         jmFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=NJaCLxCq3XCnWLFFwVYzAYFNIZQDOhDO2V5KPJHlnOY=;
        fh=8jFVrPivn9/kDacsJ7nevehv3FZKrA85eOV9G4jZP3M=;
        b=TCOW2/ZLY71sZ3yDG6S3u4u03ebILqoG9LI9MELPQJh5eCxpz2ITwovD9PwGOWomy9
         skgs4DHqfgq4BNIsF0meis+LR8WUsOesdYg7c7VQ5puLWadMEH1UfCKW/5fZz272nh+b
         M/cbsBw16tfFN14EmBoVEjnmMDVgO1+1gx9F+3cKXAROwthflfx+NrIYdr2IgcaF6LZK
         172pPu8PGH4wVrHF4I7GtTE2+Se/QnBxd6ius50QtTOk89vfb5NNT2dUOo9PPlfshM/F
         WKUtuyMyacINlVQLDTI7gdLkgZ8aySEmSFQyhN0tqluOao0cZk8TJ1k8ay8KazWCueGZ
         muYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DmWBU4Vz;
       spf=pass (google.com: domain of sj@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7704000fc75si17429b3a.1.2025.08.22.10.09.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Aug 2025 10:09:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of sj@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id BE2F160203;
	Fri, 22 Aug 2025 17:09:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 506C3C4CEED;
	Fri, 22 Aug 2025 17:09:53 +0000 (UTC)
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
Subject: Re: [PATCH RFC 07/35] mm/memremap: reject unreasonable folio/compound page sizes in memremap_pages()
Date: Fri, 22 Aug 2025 10:09:51 -0700
Message-Id: <20250822170951.53418-1-sj@kernel.org>
X-Mailer: git-send-email 2.39.5
In-Reply-To: <20250821200701.1329277-8-david@redhat.com>
References: 
MIME-Version: 1.0
X-Original-Sender: sj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=DmWBU4Vz;       spf=pass
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

On Thu, 21 Aug 2025 22:06:33 +0200 David Hildenbrand <david@redhat.com> wrote:

> Let's reject unreasonable folio sizes early, where we can still fail.
> We'll add sanity checks to prepare_compound_head/prepare_compound_page
> next.
> 
> Is there a way to configure a system such that unreasonable folio sizes
> would be possible? It would already be rather questionable.
> 
> If so, we'd probably want to bail out earlier, where we can avoid a
> WARN and just report a proper error message that indicates where
> something went wrong such that we messed up.
> 
> Signed-off-by: David Hildenbrand <david@redhat.com>

Acked-by: SeongJae Park <sj@kernel.org>


Thanks,
SJ

[...]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250822170951.53418-1-sj%40kernel.org.
