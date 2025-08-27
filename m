Return-Path: <kasan-dev+bncBC32535MUICBBPMBX3CQMGQEC2P2XHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113c.google.com (mail-yw1-x113c.google.com [IPv6:2607:f8b0:4864:20::113c])
	by mail.lfdr.de (Postfix) with ESMTPS id 502F2B38C12
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:03:43 +0200 (CEST)
Received: by mail-yw1-x113c.google.com with SMTP id 00721157ae682-71fd5f36133sf3875917b3.0
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:03:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332222; cv=pass;
        d=google.com; s=arc-20240605;
        b=KbX+NcjNJknKaJnVf23QFs2xcEcO5YyE5/4PhaqIVefRS4NZteianJM7H3thhZfrWx
         nkWVaIhGRy6+g4+sRwUCVWINNzMNvl4jvl17FXv75B+PAbjUVd14sgu7KtQcvfYvWHJ4
         iyKS49sJs3SkziHPGSEJ9Pdt5k6w+u1VgKeiDZ16UUq2MHRSX1cxGbB4fEcAokOmxdZO
         /Ws7ZJRh8hbIS1iAkFddGLkOIZ/cYtyols0ltBcCcBR6PLNcFhUB24pOwY5O+hKShaB7
         b56tk2y731liVUN5RVetDnxc9aEhDbrUAm32BNSMVBLXMCmQyh/pWYzAM3aAaNdR/jDP
         izMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=c09eSybEOFomRKQsy8z7MX1HIXLjU2rxXHcdw38a2p0=;
        fh=KONyhfVsegU1Z7rOBs1W+3yiD9LHq/l2SREco9iOIqA=;
        b=EVcyJi7bQr7c+ywjJBSWrAoXEYga61lF1AuKtX1aJndeesfDq1KCwCAvSY/ky02IaT
         KRZiW09QHNvW6ddfD2rsRDnKYsJkNYpxdOPQn5oLM7RfquySlZrahoBsOLyIurGvEXi7
         4kwAvomWKzzkpObG8m2rWBqcFXDS2Pe3gw1eXVemmlaUJBEg+ROysJG+ofCo2aYm/AMt
         TSCA0x9XedGLMwHr1OjW89fa1CGfIA9DKNlWOsATnFca0cHNVGhdbXGnjd0ya0Gvhw6t
         0AKv4pReVn58o+vILvFy5LV0Pf3G4UYvVk1J1OxLR8m4Sv0m1kXW/WdwcszfF/Utf+eA
         jSyQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=A9QSC4g0;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332222; x=1756937022; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=c09eSybEOFomRKQsy8z7MX1HIXLjU2rxXHcdw38a2p0=;
        b=W4U3hlsGGz9Cj2Gpf3jZBmwu0leUBaYdNuPWiZK+8YhHJdMgkwLLquOxTYbCXOyp9o
         aLcwob6aoOenX1nI3fHvGTznlS32vgFGiyCRq0jQ1pGJum1yiUluNA4MmBvr3G6RhumU
         +srd3+mU7CxrS6WQi/flnv4v+OB79Fok+2ixK7Tsk3aiHjlyDp3kOs/8xY8JbLMCpjN3
         LOin1n1Q4qjmKWNwiIds/Wh/DyZsoLbVkvjRX1SLEkRY5/z6CRsScNdRDKp5pNwXFpQo
         yXXS/GaUqw9Xq0KbFsxulFZnOgSLDwfBQ7b3hsaXN2xcjs9jfvQLUJbx2FEo8LrIi7kY
         aM5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332222; x=1756937022;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=c09eSybEOFomRKQsy8z7MX1HIXLjU2rxXHcdw38a2p0=;
        b=D/HoePpvT5r986mdwBsWP12NopgZUWlUlrxrpRI9KZMboXXBe/dT68lGsZEm1iG/nj
         SSObT9rWrEeNMF2blZywEwwpMMugF/XQvrLcgjNYrqUynGNgnSH8pGb8keyBLwGiV/cz
         fS8VqYPMYvVS9SBMixRB73EB7fyP0Ot1hxmUIhlbFtONgIv+2jTWrvGIUU4/no/mm9eE
         XC5kiV2HcCf5HLfFhmFTXIAnJDfF5ko8aiPoHXo0my1JS/ckDRBcOET5qASEe9jXgrvy
         BOEE5fZH++8eaaTbkQHCcRANQJprn1fCHqpomt3DPG+cdGjrQXueyN7MjCOoI7lk2VhF
         0ihw==
X-Forwarded-Encrypted: i=2; AJvYcCUs0cVpIoMRJn7njkJ5YFobY68h11nUseNSW++tlVjPboCldMYOaFNz6BTsjPg6DRaiRd0qlA==@lfdr.de
X-Gm-Message-State: AOJu0YwuvNxacZEGM/AOIww/BQQqHOy8TqXePgWp06LSKxX5++lS6MlD
	v9HUo3CC1Z5VkeF/N8qESb6LuaEB8lz8mfx0qNGIwA8tu3GEwoDzA9aR
X-Google-Smtp-Source: AGHT+IFqcN9E2NUS5CeCp8V8vItFfHoA4cM/mDeIoIRCos4V/0vihmkwz5a6IyN1rxCt+C9DGmqyqA==
X-Received: by 2002:a05:6902:1144:b0:e96:fe06:7b35 with SMTP id 3f1490d57ef6-e96fe06848amr1897769276.23.1756332221926;
        Wed, 27 Aug 2025 15:03:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfNc/yzYSLIkQbU6c5rISE5PzS4G4Xr+k5sR62FVdnMnQ==
Received: by 2002:a05:6902:2807:b0:e95:253e:d91b with SMTP id
 3f1490d57ef6-e9700f20fcbls206050276.2.-pod-prod-02-us; Wed, 27 Aug 2025
 15:03:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWz7Ty3VkKTIcj0aB8JnEsPtKura13CGeCf6jbZPQ8Q/Hb8poAQU+XpL+oXZ4BOaeSJdQthrKK+A28=@googlegroups.com
X-Received: by 2002:a05:690c:680c:b0:71a:221f:5cd2 with SMTP id 00721157ae682-71fdc31d8cfmr235087977b3.24.1756332221106;
        Wed, 27 Aug 2025 15:03:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332221; cv=none;
        d=google.com; s=arc-20240605;
        b=Lk/qUSI6KuRauSrc8HRCcgxBOGvhTjgJkzDHC9pgTR6ohXuC/IP0yKj9jh3Clhd6mf
         ZtdIRNXLLtrVgj3HE/ep14S0E2AztAOYSXT2+tzie46LGgDf1Q3D/2NjB+WIrSPSDiHT
         NwWBFBzn/jAK52gVSO6gmFbo9dlHpwXK5Oksc1U8ZJKHcJAPWYtpY4gW2+F/sFRzNQyl
         YsRVtOYrSaLWNEd7g7mCjhFlNxI/AZopzHI4qO0kmV7Okg3MnMRQPthqi5pzIN7QmTjG
         Dcmkna/GUW/GY7D+lrPKv99wKfvxVjKvS4JycPzBa5oOEPDjbXcZQh3SDZjrdOHnQ3/b
         8S0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BoCigziN+sd3886gtncwVGrOobwk0eDvjUtVkuDjFuc=;
        fh=DtvX2rQIk5H+maglZbE5ZveKzS8vzsvltXlfH2g2zyQ=;
        b=CeHjxdV330KohVDkgUsLyhw/TsttI4WuhHUYCZCqDkFS1RPoFzARlRBLLk5gzhc/H+
         FnE42Oq0umVlLrW7ry0fDbt1UupBAxlRWaHsWMOM2TFdBMUN5LBdQ248G0PqNjirQeuW
         4njgj81Us4QCAnHgqgMrGp3zsa5XIL3mC6NvK5FlGryEmzyztwY4Z8tu4JgzUrH21/Cd
         qqMlcGP/5ojIMfqGlURDGDscqI1eacwQkBMlAe5ziFxLuGr9VSYWSGX3SEPZ9curHjdy
         C4+aJJ6ZcTeAYBBhnuB9OnW401PxIjxU56PBbq3CNjsvwZetx2xb0mfN8tLwUbQYi3i9
         POtQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=A9QSC4g0;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-71ff184f3e9si5917027b3.2.2025.08.27.15.03.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:03:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-389-k0g0ERAQMDW3c6U23kRavw-1; Wed,
 27 Aug 2025 18:03:37 -0400
X-MC-Unique: k0g0ERAQMDW3c6U23kRavw-1
X-Mimecast-MFC-AGG-ID: k0g0ERAQMDW3c6U23kRavw_1756332211
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id ACA3A195608E;
	Wed, 27 Aug 2025 22:03:30 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 2E8CE30001A5;
	Wed, 27 Aug 2025 22:03:13 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	"Mike Rapoport (Microsoft)" <rppt@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
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
Subject: [PATCH v1 04/36] x86/Kconfig: drop superfluous "select SPARSEMEM_VMEMMAP"
Date: Thu, 28 Aug 2025 00:01:08 +0200
Message-ID: <20250827220141.262669-5-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=A9QSC4g0;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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

Now handled by the core automatically once SPARSEMEM_VMEMMAP_ENABLE
is selected.

Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: Borislav Petkov <bp@alien8.de>
Cc: Dave Hansen <dave.hansen@linux.intel.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 arch/x86/Kconfig | 1 -
 1 file changed, 1 deletion(-)

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 58d890fe2100e..e431d1c06fecd 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -1552,7 +1552,6 @@ config ARCH_SPARSEMEM_ENABLE
 	def_bool y
 	select SPARSEMEM_STATIC if X86_32
 	select SPARSEMEM_VMEMMAP_ENABLE if X86_64
-	select SPARSEMEM_VMEMMAP if X86_64
 
 config ARCH_SPARSEMEM_DEFAULT
 	def_bool X86_64 || (NUMA && X86_32)
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-5-david%40redhat.com.
