Return-Path: <kasan-dev+bncBDDL3KWR4EBRBZHFYDCQMGQEPPRUMXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id DAE69B39A7E
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 12:43:49 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-70ba7aa13c3sf26565356d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 03:43:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756377828; cv=pass;
        d=google.com; s=arc-20240605;
        b=TKAiV4VuB04RtYFX2GVxbly3HfDpi8I2dpTMyY9grYYV+b7uLE6VLvNiMgNeG7NDmz
         RvLdSYIN0DOI7JoFGDgo0mRfI9uKfU2Qt2g77kXGogvtvw+CzFDC/FHteroammbMdryp
         R6ANNmFCuyv1odTqrGitlDYIKTiqWXT5ZdDW6G5QJav7TaGpCj6cROpqe84mRUscowTD
         lY2KfBAI0Aet4g1k1vetXncQR17DCDFiA8rnw6XcKzVAREXNDkyISEDPAWRCxOyG9I+I
         TDWpYklxNuaPru+vQPz28GWbmFXf0HwPlvRWZz+eRAaBruMUStre5PwrFOvXls6VRWeG
         T5wQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=bYUbMLPX/Pq76+ev/nUlnTn4eWoXDHBkyhlIWIDi9VM=;
        fh=j82AFhzW9wZ61Flz373v5Smv1Gdow5VHlHALKJdjy7A=;
        b=Ul1zfnE99dDTbTCSxbgbMh78kXAkeg1peZuziqicGAvqb2pFFasSbV2aWqDJtFTMHO
         9+MEB2oJhM46r2zUZHjSm+mgP83V1tmbSH+NxeqqXxn5wByJ+CHz9hF8bBfHSHTWRrqr
         U2LbS8JvLtKX0oeZXtcEi+bvSTVhMgEXI30N198Nnu/13c3Ht0NzT4iPf/MXbML4DdwZ
         jmZ2XQP/72wYb2nY4fKHNhs/bhFporXw1UcDjKWsfV7l3zaSEV3TTpwVnA9/08jF0fB4
         hMA9gfZkAZvTxySZ/Filasm+E+FaXvVW+tplXLfBiCP4q88fV6hQ0X0tkW8MBpR5c+cb
         6oFA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756377828; x=1756982628; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bYUbMLPX/Pq76+ev/nUlnTn4eWoXDHBkyhlIWIDi9VM=;
        b=PRMkxYDtdqGV1aGtJl9baKpPuo9yAezvt5NhvzOvqO7zNO/g6TUdXjYrznHUlRXic/
         YCaD0aFZLlRfx53ChjD1g1UcPX1iJD7v2mKXFS56ebAXlIBXxvawSbsRnNMfzKQsIGwO
         QvIti74DlyK58tObFX9pEq8szShT0rCcCIS46IFRI5StVlp+6ZwdB2BQFY9T7FGEA/n9
         B1aY5OPFKCVPhkE4+H9n6NPCgVpYH2+3x53SrOps59LL/sJgZv0A8nVG7bfsr/esasMp
         CzHvkJeyfY0FQisSlYJN5yYwbpPZauARCwTRf/RF0ewl3VrTgxWNaKRkI6YhrhZJz86X
         nooA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756377828; x=1756982628;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bYUbMLPX/Pq76+ev/nUlnTn4eWoXDHBkyhlIWIDi9VM=;
        b=SqB0g5FnmahYlHBR2jTEfcH8JXZhMvh326K8hRy7m+wahLU/JKH9Ct+rxj/P0fhmil
         4+HJOHqovZ00mHyLWVyu77GS+W/6aX6BM+dYMEpM47NDnVnu5MxcT5i3zcstJQgkQ7Tk
         GgOpJ3Cg+PUE0W/6H9lxsGLY2lGHHgXVXOau6Ax/DSssfF3xNDWY1OO4BYjbF5rXR5V7
         WSV4TdxUhA3aF8iIFdUOd6WwdadfZnXwsCedndOgVnQ+pwxYKOtIJLUVyVSdrLyJ9BhO
         SJXp8q1b3NjBnVJ3yDNotKutfAwvLLVPYLtoGSAeu/3pt6iBP1KrCEcMLDYqDuJ5uerF
         b+ug==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVTNHUFSEYiWcyimSfGOTZo8BeUkTs4Ui9DCpfh3xbySJvSaQGhEYURFrqDr8R9ozzyaevsbg==@lfdr.de
X-Gm-Message-State: AOJu0Yx9sYeAI4+u98Oe8b9+PK8UJrdm/PaUyugDMm0iTwiJkv7dd7ps
	rmJ4elWaVsMOMqxM+MFx2znotgirbcvXvIbzTAW+p73dA/YD9ePdzhio
X-Google-Smtp-Source: AGHT+IHCcRxsep5hz3UbUkTU4AdjQHIukNOFiFaDxSnNF0xeMMGvmcS+c64rgq0IkMtS4PkXrSSlLA==
X-Received: by 2002:a05:6214:e69:b0:70d:afde:8784 with SMTP id 6a1803df08f44-70dafde8dc9mr183764266d6.26.1756377828638;
        Thu, 28 Aug 2025 03:43:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfk1X9oyfOjjifmwUof8uZ/8zIAwJT7+mHS7+CEEkwu7w==
Received: by 2002:a05:6214:3016:b0:709:f373:9f9e with SMTP id
 6a1803df08f44-70df009ec34ls9348966d6.0.-pod-prod-04-us; Thu, 28 Aug 2025
 03:43:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU1+5URP3iqBij2P0TT9pCkiJZmCVw5YXC2QgtUaScxn6VQ63LvBQytTIB/NcAJ+RSSS2p+nPejmq4=@googlegroups.com
X-Received: by 2002:a05:6102:c08:b0:521:f809:9969 with SMTP id ada2fe7eead31-521f8099cb2mr5109043137.8.1756377827759;
        Thu, 28 Aug 2025 03:43:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756377827; cv=none;
        d=google.com; s=arc-20240605;
        b=Yuz+wzjl1rnsI2e7+NROxJZUVAVaeY0Tphj/+HH0dvIhbns93sR1SOm5qSAQJFXjBJ
         yR2NQ7ZMV0yqZZEx6NWZ4aoQ8GXZ0N/doTCbArl2Sn6CVN8w3nQoxOdhZDgb+LFxwom4
         /OzmMALBqwlIV7K4dJ5kEV9WU2N/26r0iQVhCms8HPurzbpHroJIJMyyxQNp2kkq9n2G
         5bZAmWLPG39Ewpe+h4I8IaRpACVUD+w/nHXp2hl7zk6KfTYKkbmZKyrFA6I6iKn9IGZa
         ZHgG05DJUwKPEmktI14gbJ9wwSDxSoP4qsTeJ5rhzsZ6FB1GFikMxCEQmTPMGNIdli+m
         UQaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=OsWKyS8lqER0Tz1n2hSl101cY0gnWMD3HdL+I/Wazi8=;
        fh=ywTX4AlbiVxu+MU4mcxpyWFYl1ZLGQDdyYHPei8QJzA=;
        b=TB/tIM4BIYePaV5sHvWCF1Pbt2IbAKcdrEKWeBlQikNFXqZLYhnfotIyn+F10SC9P1
         hiawRfZKRSlqkUkRcAFdGDduTIVzUo+2ftkAFm0t32J3u7gYJlmc32mtRde1OBormqzT
         0tk3gf63kjCdlxYjlBaj/xggb2z/8CHxIXVCVtFpRMBGSBe+9KVB4uKcCvkI8yPh/9ym
         2LHvaOktnUF84RMAM9t/Duv9Jh1pPUbrcAOHiLweJ6RNj5QusQz2v9BnPU17T7rj7tx4
         SkTV8VbZeHodofu4Sds+8XP4cvqDWWHlrNUJyrKYW6RKYWp5bZOdpOpLs8PpbPQbjfqs
         9YNw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-8943398312csi14573241.1.2025.08.28.03.43.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 03:43:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id B18064361B;
	Thu, 28 Aug 2025 10:43:46 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4E7A7C4CEEB;
	Thu, 28 Aug 2025 10:43:39 +0000 (UTC)
Date: Thu, 28 Aug 2025 11:43:36 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org,
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>,
	Will Deacon <will@kernel.org>,
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
	Michal Hocko <mhocko@suse.com>, Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH v1 02/36] arm64: Kconfig: drop superfluous "select
 SPARSEMEM_VMEMMAP"
Message-ID: <aLAy2GJ9YuNgvxCd@arm.com>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-3-david@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-3-david@redhat.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 172.234.252.31 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Aug 28, 2025 at 12:01:06AM +0200, David Hildenbrand wrote:
> Now handled by the core automatically once SPARSEMEM_VMEMMAP_ENABLE
> is selected.
> 
> Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Signed-off-by: David Hildenbrand <david@redhat.com>

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aLAy2GJ9YuNgvxCd%40arm.com.
