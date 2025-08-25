Return-Path: <kasan-dev+bncBDZMFEH3WYFBBEUZWLCQMGQELTI72JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id EB888B346DE
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 18:17:23 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-70d9a65c355sf70217046d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 09:17:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756138643; cv=pass;
        d=google.com; s=arc-20240605;
        b=HuC+XvSpW4Hl+6nSnoiKnxDkoC5yxf5mAphExhpiZ+odi84CzuEMgwxw5bjkNm+D6H
         fs1MHwg+AScZK6SOWZJTA41J+WqIiDwID6UJs/T2pZiAHzmeBQEIiLPUNTYZLjOoS1Zt
         c4JU61qf+bN83GuxtHO3/dGKdeybL94RtpaxlxuolESDtenr/bAwUYl/VIRwXHmsmkTB
         rdMxQzVwDw8kE7L9b+RgTiiuu2PkiZ0xV3cy24aLuThAYH5HPCrUDyGZGhymnK+x/XS3
         kG+Nl8JXAQrTgr2k8lWC/N0MuYejtNFXmB+RxzZa5y6FJyFK4nm2BDpDRvuBxrojtCtK
         dHcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=+h+tqajgDWAO9Pd30ErHT9OOl7bJngcys/OrNSbKTHs=;
        fh=PmSUpP3nDDuX04QOXjSrWFi6MFXvaRdfnU/fE31TTOQ=;
        b=FvN3PjjZ+Q5CA6BjHxDOBeZFa+afhMynpikhedlqAZq80UIeFcjCGmzl4o3TEafahn
         Z03BJKv29HJs0wPn3rxGmljlcyoaZ5yh+KogUyjEabTVLBn/hY3Bvsa3LY2/IutKy9+k
         0jvII3ccpsAmBDaVgRfVos/ptqMXcWLo0T3+y4AkOC9rzOCJ3+/AU/wiWIRGM/BaNGzt
         zkCmL2qsHWFIfuiTzwu1pe8QH7hxRvsMicIm0tY/jyl2XYC3vurjQ7YMiE8EpcuACSYL
         VB0aNcvW+FaM/kdWdC4OQI+bALscy5xBWgG7hpAnwiDHmn0qq0gOvMKR6BUhs4jJFh8d
         Dnag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Z1X+B0ZG;
       spf=pass (google.com: domain of rppt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756138643; x=1756743443; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=+h+tqajgDWAO9Pd30ErHT9OOl7bJngcys/OrNSbKTHs=;
        b=Wi/kvIFGmDXSHixK+pjP8gQ4TH/nVtrUlc26EClyiGT1Iju2x3h761RNP5rWoFbqVD
         Lx/LncXU++Dml+12o29FyOvvD1uTPFRF+irEyaekZJ5mj1hsnPSm/JBEm2jaT/eTP6Rc
         lDxgOvyqWsarVOmwXGxRdl8SVrFhodOlJ50NoAFsU3d9rMfFr6EtM4bKCYCHAn0U8syQ
         VnzChzrnCOMuaHUXiKdn9yYZy8txORLDm0FbMPYJRMhpSwk/5Fe/knvV0kM22ZG/7mqa
         J1MIj4a2BQTU+qFZ3BFReaAz5oEqtfAx51yHe+30Tub/3+NBnY11DoIiMem/mBz812jW
         aePg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756138643; x=1756743443;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=+h+tqajgDWAO9Pd30ErHT9OOl7bJngcys/OrNSbKTHs=;
        b=guH+CZGq9trvLiEct6E/uewDvAEGSYKSVNAaKS6mOcX8Q0OalrHBgTiWbYabwA3cBu
         NcLtbdQoUZMes7CTVPRuRVuZDXXtL7wD9mfR1yK03bObpfbeRaAjdyfJyCQBK5UsmfcF
         FUjJjdFP3nFlmAMre81MzoPnm0hCCPSZzs9IjZR6GSmoZ+xBvY0F8twOhdy5E7CxZ2Ai
         PRj53LIEPs1CE9yjJA4WgPExmy9iCIFxz2JP1s10OTvFniKfYB8EdKhQDaKryqpOdBVb
         LaulYlkpQhw/P/uRfv5maRrk07ghreKjcbDb5H43SCVWnqvEX8RNrkBTnhYTvRUP6vTo
         eLDA==
X-Forwarded-Encrypted: i=2; AJvYcCUGyxMeoIsP/TK9495AlcCZ6QK+WcbZWS/zy2GlBeQRVGISJoSqIfQAogGy8HvUaikhgpVCLw==@lfdr.de
X-Gm-Message-State: AOJu0YwSrpMjZksdnfkl/fbe8Ek7G8QBfFxLM7WxaxgPYRi4SdVlusVi
	LTGB9YP6FIBZ0bp1JXKYCQrfC6fX92YQAJg9m6AQvNH2O8eNzMI5NGMC
X-Google-Smtp-Source: AGHT+IEBSWSTdVlaZhS68OuBDup60Um8ZlcRhzvUFfIWm3vWG7h1UQbS/Gu+ecsQv9PQA9YZdfnJjg==
X-Received: by 2002:ad4:5ae5:0:b0:70d:beed:b357 with SMTP id 6a1803df08f44-70dcbd879dbmr2775376d6.1.1756138642437;
        Mon, 25 Aug 2025 09:17:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdcEtRHageZ6pw3dI2k7uF2S2fSnnGaARkYWx/GNMT+bA==
Received: by 2002:a05:6214:240a:b0:707:5acb:366c with SMTP id
 6a1803df08f44-70d85c3bc52ls52615166d6.2.-pod-prod-00-us; Mon, 25 Aug 2025
 09:17:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXC82KhvaacKe092zGBx60Dd+KmQjWN2GZH9/SsckI6JkfMiYgt8Y4hYLF0JzL5SPaVreT34BYAdy8=@googlegroups.com
X-Received: by 2002:ad4:5fc7:0:b0:70d:b960:22d9 with SMTP id 6a1803df08f44-70dcbc3a73emr3527626d6.0.1756138640804;
        Mon, 25 Aug 2025 09:17:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756138640; cv=none;
        d=google.com; s=arc-20240605;
        b=KKnkr34MBdl460A8P+xk9UfjsBxheB9qZv7Za49yBxpHvYFNb23icoKf8xlkdJiWAX
         kd1G/nAyW5EbIRmbNvHSlSkX8g7OsqWz1Dq5W9Bn/8NzL1l61T4QwzY7dW8xjpeCS1S/
         aolzXzFvKb+YcdKkdjzo4oDDLGeZaiYgxg+EWqidWRqbSi+a4t0nCP+BLnODpZFmUjR6
         XnJaemqQqUTPZrl/Brm8ZQvYAthI2nMZP5f9Jbk6u1kzfI95hHoKUPzcb2+wJ0xaVgbr
         1JPdGtnqzZyu4sNubs+jEBebxVGLH8RKlsCcTN1A45+ho8OHIvflLMq+I4OJlhCI4+ZP
         OEnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=yaUcnQjozmvTYDYURkWMjBxCsSnXy41d7hzIH1GSQGQ=;
        fh=SnWEHMnw6q5A1i5gHssHZhjXePV2/MD17aPBvTeFLno=;
        b=ZNzyoWT1N0MKpMgNaqDMw4IBw6smzkDexNwTS7dwL2PGtOdnr0YV6tr2RyfHyI02QA
         B/45ZL/D3/QSXaZQjuE8j2rm99nPyyETuuIa+mUhAP/G5zKuWWC44Jt21qelhpfgg3T5
         BTbtWBp0ZQA6Cedh7wcGjBoyeQpgcgQGlO8eHXiHzAH7b4CZW2HhWR5tRcF6+n40qoye
         a4h3ZWesxa4u2prqC3OcBt3458PKXm4fdlU4iXLkoCaLhLLIZ1Ne+ZI43Xcx6iapsB6N
         CSXmXuihrk9OHoNGA72nPsx9QCxBvfXebs73XA0lkhO1fGSm5yZy6as2JFAQ+L5u4yMO
         NQ7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Z1X+B0ZG;
       spf=pass (google.com: domain of rppt@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70da7265ad9si2623906d6.8.2025.08.25.09.17.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Aug 2025 09:17:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 523095C5FB5;
	Mon, 25 Aug 2025 16:17:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3323DC4CEED;
	Mon, 25 Aug 2025 16:17:05 +0000 (UTC)
Date: Mon, 25 Aug 2025 19:17:02 +0300
From: "'Mike Rapoport' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: Mika =?iso-8859-1?Q?Penttil=E4?= <mpenttil@redhat.com>,
	linux-kernel@vger.kernel.org,
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
Subject: Re: [PATCH RFC 10/35] mm/hugetlb: cleanup
 hugetlb_folio_init_tail_vmemmap()
Message-ID: <aKyMfvWe8JetkbRL@kernel.org>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-11-david@redhat.com>
 <9156d191-9ec4-4422-bae9-2e8ce66f9d5e@redhat.com>
 <7077e09f-6ce9-43ba-8f87-47a290680141@redhat.com>
 <aKmDBobyvEX7ZUWL@kernel.org>
 <a90cf9a3-d662-4239-ad54-7ea917c802a5@redhat.com>
 <aKxz9HLQTflFNYEu@kernel.org>
 <a72080b4-5156-4add-ac7c-1160b44e0dfe@redhat.com>
 <aKx6SlYrj_hiPXBB@kernel.org>
 <f8140a17-c4ec-489b-b314-d45abe48bf36@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <f8140a17-c4ec-489b-b314-d45abe48bf36@redhat.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Z1X+B0ZG;       spf=pass
 (google.com: domain of rppt@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mike Rapoport <rppt@kernel.org>
Reply-To: Mike Rapoport <rppt@kernel.org>
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

On Mon, Aug 25, 2025 at 05:42:33PM +0200, David Hildenbrand wrote:
> On 25.08.25 16:59, Mike Rapoport wrote:
> > On Mon, Aug 25, 2025 at 04:38:03PM +0200, David Hildenbrand wrote:
> > > On 25.08.25 16:32, Mike Rapoport wrote:
> > > > On Mon, Aug 25, 2025 at 02:48:58PM +0200, David Hildenbrand wrote:
> > > > > On 23.08.25 10:59, Mike Rapoport wrote:
> > > > > > On Fri, Aug 22, 2025 at 08:24:31AM +0200, David Hildenbrand wro=
te:
> > > > > > > On 22.08.25 06:09, Mika Penttil=C3=A4 wrote:
> > > > > > > >=20
> > > > > > > > On 8/21/25 23:06, David Hildenbrand wrote:
> > > > > > > >=20
> > > > > > > > > All pages were already initialized and set to PageReserve=
d() with a
> > > > > > > > > refcount of 1 by MM init code.
> > > > > > > >=20
> > > > > > > > Just to be sure, how is this working with MEMBLOCK_RSRV_NOI=
NIT, where MM is supposed not to
> > > > > > > > initialize struct pages?
> > > > > > >=20
> > > > > > > Excellent point, I did not know about that one.
> > > > > > >=20
> > > > > > > Spotting that we don't do the same for the head page made me =
assume that
> > > > > > > it's just a misuse of __init_single_page().
> > > > > > >=20
> > > > > > > But the nasty thing is that we use memblock_reserved_mark_noi=
nit() to only
> > > > > > > mark the tail pages ...
> > > > > >=20
> > > > > > And even nastier thing is that when CONFIG_DEFERRED_STRUCT_PAGE=
_INIT is
> > > > > > disabled struct pages are initialized regardless of
> > > > > > memblock_reserved_mark_noinit().
> > > > > >=20
> > > > > > I think this patch should go in before your updates:
> > > > >=20
> > > > > Shouldn't we fix this in memblock code?
> > > > >=20
> > > > > Hacking around that in the memblock_reserved_mark_noinit() user s=
ound wrong
> > > > > -- and nothing in the doc of memblock_reserved_mark_noinit() spel=
ls that
> > > > > behavior out.
> > > >=20
> > > > We can surely update the docs, but unfortunately I don't see how to=
 avoid
> > > > hacking around it in hugetlb.
> > > > Since it's used to optimise HVO even further to the point hugetlb o=
pen
> > > > codes memmap initialization, I think it's fair that it should deal =
with all
> > > > possible configurations.
> > >=20
> > > Remind me, why can't we support memblock_reserved_mark_noinit() when
> > > CONFIG_DEFERRED_STRUCT_PAGE_INIT is disabled?
> >=20
> > When CONFIG_DEFERRED_STRUCT_PAGE_INIT is disabled we initialize the ent=
ire
> > memmap early (setup_arch()->free_area_init()), and we may have a bunch =
of
> > memblock_reserved_mark_noinit() afterwards
>=20
> Oh, you mean that we get effective memblock modifications after already
> initializing the memmap.
>=20
> That sounds ... interesting :)

It's memmap, not the free lists. Without deferred init, memblock is active
for a while after memmap initialized and before the memory goes to the free
lists.
=20
> So yeah, we have to document this for memblock_reserved_mark_noinit().
>=20
> Is it also a problem for kexec_handover?

With KHO it's also interesting, but it does not support deferred struct
page init for now :)
=20
> We should do something like:
>=20
> diff --git a/mm/memblock.c b/mm/memblock.c
> index 154f1d73b61f2..ed4c563d72c32 100644
> --- a/mm/memblock.c
> +++ b/mm/memblock.c
> @@ -1091,13 +1091,16 @@ int __init_memblock memblock_clear_nomap(phys_add=
r_t base, phys_addr_t size)
>  /**
>   * memblock_reserved_mark_noinit - Mark a reserved memory region with fl=
ag
> - * MEMBLOCK_RSRV_NOINIT which results in the struct pages not being init=
ialized
> - * for this region.
> + * MEMBLOCK_RSRV_NOINIT which allows for the "struct pages" correspondin=
g
> + * to this region not getting initialized, because the caller will take
> + * care of it.
>   * @base: the base phys addr of the region
>   * @size: the size of the region
>   *
> - * struct pages will not be initialized for reserved memory regions mark=
ed with
> - * %MEMBLOCK_RSRV_NOINIT.
> + * "struct pages" will not be initialized for reserved memory regions ma=
rked
> + * with %MEMBLOCK_RSRV_NOINIT if this function is called before initiali=
zation
> + * code runs. Without CONFIG_DEFERRED_STRUCT_PAGE_INIT, it is more likel=
y
> + * that this function is not effective.
>   *
>   * Return: 0 on success, -errno on failure.
>   */

I have a different version :)
=20
diff --git a/include/linux/memblock.h b/include/linux/memblock.h
index b96746376e17..d20d091c6343 100644
--- a/include/linux/memblock.h
+++ b/include/linux/memblock.h
@@ -40,8 +40,9 @@ extern unsigned long long max_possible_pfn;
  * via a driver, and never indicated in the firmware-provided memory map a=
s
  * system RAM. This corresponds to IORESOURCE_SYSRAM_DRIVER_MANAGED in the
  * kernel resource tree.
- * @MEMBLOCK_RSRV_NOINIT: memory region for which struct pages are
- * not initialized (only for reserved regions).
+ * @MEMBLOCK_RSRV_NOINIT: memory region for which struct pages don't have
+ * PG_Reserved set and are completely not initialized when
+ * %CONFIG_DEFERRED_STRUCT_PAGE_INIT is enabled (only for reserved regions=
).
  * @MEMBLOCK_RSRV_KERN: memory region that is reserved for kernel use,
  * either explictitly with memblock_reserve_kern() or via memblock
  * allocation APIs. All memblock allocations set this flag.
diff --git a/mm/memblock.c b/mm/memblock.c
index 154f1d73b61f..02de5ffb085b 100644
--- a/mm/memblock.c
+++ b/mm/memblock.c
@@ -1091,13 +1091,15 @@ int __init_memblock memblock_clear_nomap(phys_addr_=
t base, phys_addr_t size)
=20
 /**
  * memblock_reserved_mark_noinit - Mark a reserved memory region with flag
- * MEMBLOCK_RSRV_NOINIT which results in the struct pages not being initia=
lized
- * for this region.
+ * MEMBLOCK_RSRV_NOINIT
+ *
  * @base: the base phys addr of the region
  * @size: the size of the region
  *
- * struct pages will not be initialized for reserved memory regions marked=
 with
- * %MEMBLOCK_RSRV_NOINIT.
+ * The struct pages for the reserved regions marked %MEMBLOCK_RSRV_NOINIT =
will
+ * not have %PG_Reserved flag set.
+ * When %CONFIG_DEFERRED_STRUCT_PAGE_INIT is enabled, setting this flags a=
lso
+ * completly bypasses the initialization of struct pages for this region.
  *
  * Return: 0 on success, -errno on failure.
  */
=20
> Optimizing the hugetlb code could be done, but I am not sure how high
> the priority is (nobody complained so far about the double init).
>=20
> --=20
> Cheers
>=20
> David / dhildenb
>=20

--=20
Sincerely yours,
Mike.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
KyMfvWe8JetkbRL%40kernel.org.
