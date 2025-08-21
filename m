Return-Path: <kasan-dev+bncBC32535MUICBB6PYTXCQMGQEJJOW4UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B002B30365
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:07:23 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3e56fc142e0sf17960525ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:07:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806842; cv=pass;
        d=google.com; s=arc-20240605;
        b=UNGIuMBqfK0AGhJ3I5WfBFCCfxmu7+LST77Dr5CFpZ8Kq+th23grJGJ0bHx9fTlyfh
         54bMHTwPNRKCOIjVkn9elTpG3WGEdi+XK2k7SO+V9OKbUJkJLJ0JdLewubz7NY7QC8fR
         ynxUQ8KyHP3ndRA/3FN0H74voA8vyMDKlvYfUuRtDGqYwdi396AeCnPF98fgwVX2ShHR
         gELClRKuKrD9odnr5UJ0XAJdouHUoHLdbbg4E5wrf+cJQJGJVTTM6HgwDgXQb0GazcA5
         2CNqVIPsY6njpUo/JYGQbQ6MxrdVWhf1bgBLuOL8VKfxlNC1xukklNGz/S9Zk49ruj4e
         0a3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=xwJUYGEi6sMDJEW3c7MjJNSusW7nYeY1Xs8b58t26F8=;
        fh=ejXbon/dbT5SY1Q4LA70pJVA/Bfep1lRUePk7VfCfzo=;
        b=NLE1PLZipERDosSlVhAtRhSW38gTdqMOdevbUCiGOz5u+Jke4A3MlMg2sA8udJf6z3
         tC+FFdc6vv8aq9YuJE8A5YyfVMWju9Wna1Fny8OxaO6yx5ipkjqEmA0HRW/Xd/vZ8TMJ
         VoPK1miR0fL4Die6ycMYXuMHELkbLDqPPAzEKXLXJN9CHex2GeR+3RlrCF6TKwD7p4X6
         klfXB69UgcZs0/zEzsgdsvuD7zVXTnBk5fEQ49YbQr6NfVdh+pFa8Qma3Pl8j6pZtYq9
         nhKnIiUYON9acTKgpeSZq3xZlKkeM6O5+2dim3X97btaKDsS2tNue7wor8+B+aSBvVq3
         CNrA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=eZz2HS5Q;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806842; x=1756411642; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=xwJUYGEi6sMDJEW3c7MjJNSusW7nYeY1Xs8b58t26F8=;
        b=mCM4b7NM+XRz9R2sjlFWaw3pwopGnS+PWdvejXtrvEqt4qGS9IRkTzJTpazpu/ahEi
         nqonPi2arEikDVrQSEHFZvoRSdUJcJXHMCtWdNOAjgYlyZdudFXDkh3zLtOHF42WdwLH
         q7w490ugzzKHG8WZSptaCe7PG0Hj43UUMX37ZnKFR4iV1W4HvVBh1dxiV7Vu5G7OFV0D
         bfqSDzdDJTNw1FHZ5Qbhfv4j335CNV7a6udySdku2W7bfNS445honHp05gBGZvovaeFd
         J0N3a77Ng3bOLySXrExmctSeDPQC6u0LxESRDQ27KjCCwAvXyTKxx5SKi28Q3r3BGopo
         8+cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806842; x=1756411642;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xwJUYGEi6sMDJEW3c7MjJNSusW7nYeY1Xs8b58t26F8=;
        b=VW2KFnfNFajkmpl3vgYvQNo/aT8iV2wPGW2UqFbbRi0UVnRZRX6wtIbBnBnuzm+kFY
         XuoSszFtwFruM3oJkTepfad07pvZ7s8Hzk0WJmNB8vp3Keblxr5rEda0+lv/VbAhEyQe
         s3kuidiEamMD48pQfvQt54OFOf97LNz4+ha6sjpfYc6pKsQ4jv9QST9t4XRrVs52gEsP
         HeNhwvSBUX/bWjirJz2/2XlhYw13joUIKN1UIWl2FOWPcd61xz5hz8f/8LQDqbrkzJDn
         WdKJxDmtWB6lWrx4aSKpDNTOXws63/17udAtFg64u+VDnWXgBs/XADVN18u7bj6evepU
         gtAg==
X-Forwarded-Encrypted: i=2; AJvYcCXS7RxH0W4xXKRBEBrlPKnqDTLxbgRiv7uXuBcwPl0VL3VXoBPDrr8LXu8pLXfdcKCbdNZu0A==@lfdr.de
X-Gm-Message-State: AOJu0YxyuVzpYrKrYvnd68y81XDF1/iukVzz23Td++b72opafeaZzpcI
	SdNnMrXZn8JAxK5/vStY9JJCIofLrNPtYHnwwD58pJAOP13ddJ9vfP0V
X-Google-Smtp-Source: AGHT+IGsBJXu7zZrApmD4E/U1XlOa0WhDIdIeULqWV/7cBPKaynIhf5JCiZ2EpIPCIwZF6eViLhXsg==
X-Received: by 2002:a05:6e02:3786:b0:3e5:7e04:2b1f with SMTP id e9e14a558f8ab-3e92dd017acmr9163755ab.0.1755806841747;
        Thu, 21 Aug 2025 13:07:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfT22pJLzGjKUnEM88/Rj0xxBu3TmzpbMmPuON1NZW4hw==
Received: by 2002:a92:c5a1:0:b0:3e2:b5c4:3547 with SMTP id e9e14a558f8ab-3e67c3a2e88ls7854755ab.2.-pod-prod-00-us-canary;
 Thu, 21 Aug 2025 13:07:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXi8q91Zk8OLwgApABdEBsfadcgOwNbS2XlzOTeA6UKH3y00Z/3DzeILygMXxmJG3HhrboCFx6XBvU=@googlegroups.com
X-Received: by 2002:a05:6602:2c10:b0:881:8067:ba37 with SMTP id ca18e2360f4ac-886bd6ca1e0mr102233539f.4.1755806840558;
        Thu, 21 Aug 2025 13:07:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806840; cv=none;
        d=google.com; s=arc-20240605;
        b=aI4LSEKTeO605rQXaQ9NcxGSXuYTYbSdMU8UpesDYFhiABI4NFk+hli4G7cTBWnQAK
         X0zrVRuZBM4NNHhSJAkP0+Q0Yu+wKV3o8WNPF6I82N2LZUzNe6Nog/QL97JpUewAAWvI
         mSWp+HSG7Q/6Akc/liM6BNYZUACej6z/lK/+H9JPA/yXB1h7UQvxH4+TTb+uYzRAug6z
         noeNymkSVQPedlBMlbPUJkk5Ial6jG1E5HByKIk9sSWHEKYHPenJrrfsfGx2fZvOX7Sw
         vV8lyD13fEfvUBkXfG7SLdRX2RQQRvYwCix+ZM/3STPmHog0m6aHvJfarQ4p/VLURXYz
         m27Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Zfh98TqNQqR9uCNr2hB5bEgIJ/15ql7Yv0zNbj5EC/8=;
        fh=qugllHCq8DjhiEcfn2nzGmU/H3AzljGkFajS1qDyNiI=;
        b=RfUW3/AkAOq6J7bVeGG5U+2gDMDwcsLUI49jt2TNAUAZpKm330y7n3wuHqlZHYAUdv
         hgjIofnA6RxWaKw1eUG7mP0ZyqDY4HUh9abx1VQ/qG1CAtTnD1F/ergIjDGGVzDYURo9
         rM1a8/wNeIfy5npjh1RRl5YSpeVKw+8cQFEG1FXOu39HulN+jaLAPY2fTQ7JbOBAm0rl
         7Nsw4B539pYEBdYzQ3coeovsL5XHfS+So1R+IC4xR7t12dRsV6tYqGmHfA7dtxd+3ZHd
         OCd/gXOB/BrreqEPEnDx11sZQIc2mh0FgJ+kx1tSgs9gPfzoaAvd9O57j23zQ4vbVVan
         MTqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=eZz2HS5Q;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-8843fa41831si71331639f.4.2025.08.21.13.07.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:07:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f69.google.com (mail-wr1-f69.google.com
 [209.85.221.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-177-onPSDmcxOv2nHcgv56sTNA-1; Thu, 21 Aug 2025 16:07:17 -0400
X-MC-Unique: onPSDmcxOv2nHcgv56sTNA-1
X-Mimecast-MFC-AGG-ID: onPSDmcxOv2nHcgv56sTNA_1755806836
Received: by mail-wr1-f69.google.com with SMTP id ffacd0b85a97d-3b9edf41d07so651719f8f.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:07:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXiHUDqY8rNhjecwML2rUdD5Xo4A+6lDEqFPU0RhqDqMBcRe2pJ2PtDK0vSphAfGXR433eoXsXZmck=@googlegroups.com
X-Gm-Gg: ASbGnctrITM/NmYVmDNHuFgE58us4p/1T3Bxt4UTtpXMnkmVl15lBUPslcYpj5LVZmc
	SevnQs5L3RNFzEKdGVqkUXMkWe4VmlSylC/aaTa91AErG5rKwbsRd+FCE/mWS+wHMx2QhcMXDVQ
	uP2lgGaVekGyoWMPzMsm6ZLLc2LLgjSOB0sv2xM5TZ+IXi2q6+ppanX1n0oVh1hloTDREakzZo9
	mCniK1HIqzSx0pDtwOQkFSlw7UDquKPGeoLhYRdiY0bZroqnFrgAZJ4qI+8J3hxT1yyy13mF3v8
	k50pD5xHqTQ1p5qVmDY23rDvlxHfKiak9/x93OXcKJDZGV+bK+NdOaJ02zob24me/RutJnrPbbB
	GwsPYfCzG1DyIAen8PhW3yQ==
X-Received: by 2002:a05:6000:1445:b0:3a5:27ba:47c7 with SMTP id ffacd0b85a97d-3c5dcc0da36mr162965f8f.48.1755806836119;
        Thu, 21 Aug 2025 13:07:16 -0700 (PDT)
X-Received: by 2002:a05:6000:1445:b0:3a5:27ba:47c7 with SMTP id ffacd0b85a97d-3c5dcc0da36mr162946f8f.48.1755806835650;
        Thu, 21 Aug 2025 13:07:15 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id 5b1f17b1804b1-45b50dc00a8sm10958175e9.1.2025.08.21.13.07.13
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:07:15 -0700 (PDT)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Alexander Gordeev <agordeev@linux.ibm.com>,
	Christian Borntraeger <borntraeger@linux.ibm.com>,
	Sven Schnelle <svens@linux.ibm.com>,
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
Subject: [PATCH RFC 03/35] s390/Kconfig: drop superfluous "select SPARSEMEM_VMEMMAP"
Date: Thu, 21 Aug 2025 22:06:29 +0200
Message-ID: <20250821200701.1329277-4-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: Xujvs6b3qIpMWyNmnBm26nejPS2jOrlrZIVYA2mo74w_1755806836
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=eZz2HS5Q;
       spf=pass (google.com: domain of dhildenb@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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

Now handled by the core automatically once SPARSEMEM_VMEMMAP_ENABLE
is selected.

Cc: Heiko Carstens <hca@linux.ibm.com>
Cc: Vasily Gorbik <gor@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Christian Borntraeger <borntraeger@linux.ibm.com>
Cc: Sven Schnelle <svens@linux.ibm.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 arch/s390/Kconfig | 1 -
 1 file changed, 1 deletion(-)

diff --git a/arch/s390/Kconfig b/arch/s390/Kconfig
index bf680c26a33cf..145ca23c2fff6 100644
--- a/arch/s390/Kconfig
+++ b/arch/s390/Kconfig
@@ -710,7 +710,6 @@ menu "Memory setup"
 config ARCH_SPARSEMEM_ENABLE
 	def_bool y
 	select SPARSEMEM_VMEMMAP_ENABLE
-	select SPARSEMEM_VMEMMAP
 
 config ARCH_SPARSEMEM_DEFAULT
 	def_bool y
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-4-david%40redhat.com.
