Return-Path: <kasan-dev+bncBCC4R3XF44KBBHWFULCQMGQE7OTIEEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id D7D14B320EE
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 19:02:24 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-61bd4dcf6b8sf397182eaf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 10:02:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755882143; cv=pass;
        d=google.com; s=arc-20240605;
        b=dyWQiUId+OLuXOZPzdFn+KvsyOwZHqWV2TBmXVSZW3aj4bhOkuKDm1j47PSg//4u1R
         tujklXRVM11Ko38M8ZbonlD7u5JV+/o4hDeTLiU0/5bnRQEVqOXtxd8iM9RwGlkTih/l
         ulkzyydXnZNGbSO2Xk0QFxw/AIrQuRHmz3mBWWiA+gEG2aneOplONBFwAfb2Zjp1n2d6
         TcnINuSXHjZjzVJukDhgPwriKslcf1CJw+3HZ/VMmXWgXARUUvTEeKF1U6QLVqkrucbJ
         T24HTOsz3U6SVyDqmKY/JKbLZG0HKEe00sxCkl/HoAhEcEqVTUdBG1zpxP+7oMkww4kM
         izYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=wRi3yYvucOARW9osjPrCZRMojH9EayAQx+MfR1pFxR4=;
        fh=YgIN90UcAUOakNuytpQgOdmwFtfBASli8WPLZJLjjPQ=;
        b=dcrWSS16x29yATxZoDYi3GRaSmxv3H5GCRKz0GOuxIHeXAYMAr7rWqno1Z9nQjHq/v
         P0+NkJX2S3p2fYhNZUoqY3fnPF1RrXIcQfdN0uhATeISPEhgyxQi6TWdZg1yVkT4o1cl
         f+RX0/TB844lWv5W8ni4ih8sqxXaGzY1+k0xw9N+WCBetEO/NdWf004eG3DDF6LW991x
         dqqgSL6ufzdNkcPTYz7AMROhZJbakAPcZLOSVKbUIMfheItGXgxDJGYkVs9Qdauqpy7a
         Xg3joyS8aCIR/DCpUQYYjuNgwlfJ4oRF6yedJCGTn1rQoaPOfuTgvFsxbClJ0XV/I9pi
         2wew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="X/RxlEh5";
       spf=pass (google.com: domain of sj@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755882143; x=1756486943; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=wRi3yYvucOARW9osjPrCZRMojH9EayAQx+MfR1pFxR4=;
        b=Ga4tJhqrwJxfjFiJTfCDBVv9ur+J8sC0RTtulP2O2etnbTNBvlmUZ75r/pRI7NAoB1
         k908Y6WDFVA0RJvvwjO8c8Dbrg7gl9QSWSF9d7zJSNJCu+zWo8fPpw6HhgH0hMOjnJPk
         E6LPCnqojJ7v9TQSgJ9RfN75tkzLFEAIsPxtDHyV/jy94N8PhdtQpQ3k4TCIZctygHQs
         i46iiJlcGoR9naIVk0WAFOdF1xFgF3jRLgesr+jvpKv9xXywc0VAyUFMdQDB+PpALeyl
         LzUAQdh91Qej7dn02cSipLhXD9FW3BDuzKI6v0epRXVNml7m3pnJqMWiSeA2Fk+RwK+G
         N2KA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755882143; x=1756486943;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wRi3yYvucOARW9osjPrCZRMojH9EayAQx+MfR1pFxR4=;
        b=nP6yH4CwxAzgWUYCPsfL5IC8EkpOGzxjMmVt13vt437ariBFqRrgxRl46fpRJqOyyL
         6sEwV6pnsG/0oEIBrAM87nO94EsMNC0A0y7ocYo/9II/QwEid5Ie91yky+bHSDXR+qwu
         53dGKQ06348crMNp09tNPIVPCYeqW9Mn+RVeooc9ltu+ak4Wze8OivoPudDObcy4xYL4
         a4J1oac/6KHyTnJmJDFt5y9wbi+7IAPJGgjis/gjkqopS5E1VXJt5b7ntZg3pGZxNvaT
         GLmTnRzb0kfkE1Tey66iDdG5ErMZKSQb6nb+Y9A+t5FPiJWt4bDzngU57uyz8BSs/FPM
         uKXQ==
X-Forwarded-Encrypted: i=2; AJvYcCVbzZcyHlWthk7AA+eV30nswa2Sk4aIFapMKQSi5EEGniCYMyOv0J1xxJouHEY6syrbpBDH1w==@lfdr.de
X-Gm-Message-State: AOJu0YwvgZBRx+vnIEf0o+3xRW7I3riO6Ivn/z/LcTc8rucSwpY4qCdN
	fbzngHpgJIBm3sOtkXITOxeaeedFhXYFLrn06cmndevwsUax61Mhdxt2
X-Google-Smtp-Source: AGHT+IG7MDYMOwxSwa8qrM0LYWcXjyapbkKCod26aTBEolZZJy8a2pt/mNzvmuTt/5Yc5iW0dP5nVw==
X-Received: by 2002:a05:6820:61e:b0:61c:387:b4bf with SMTP id 006d021491bc7-61db9b5a10dmr1580640eaf.5.1755882142911;
        Fri, 22 Aug 2025 10:02:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd8xzR9KFS9ZREKotGfMLokrBbkYT5WnNQFggjKuplMmw==
Received: by 2002:a05:6820:8c4:b0:61c:c4f:995 with SMTP id 006d021491bc7-61da8d729c5ls453154eaf.2.-pod-prod-04-us;
 Fri, 22 Aug 2025 10:02:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWUBRl/8U/tTFMu3SvPfQILmw9GkcNf2GYm90HlAEEwUMIzLX0+qAHntq1oh0dKqNGFT+quTj4JiHg=@googlegroups.com
X-Received: by 2002:a05:6830:368e:b0:744:f112:e537 with SMTP id 46e09a7af769-74500aface3mr1882565a34.30.1755882141355;
        Fri, 22 Aug 2025 10:02:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755882141; cv=none;
        d=google.com; s=arc-20240605;
        b=LPWTW/3e330hw2TwOHHBdmtFyQZvqa9Zw/zFbqOo/8q0jzvNXsBUy+2ogQTrJ4NloK
         i/NOwqmTL4kkhsxXnLswPJ1pomng0zQ3wK4nqMXjP1/ASULkfAaIbYYpV8G0Ntf4/f4p
         O+EYD1e/ZvNDxvwU4NVbzmMyFc0QwLLMfERBXFm/WKmUQq/Etio6o1zaifptrnFTEdzB
         dDZxJpKIWQ47pG5N2Y5ngHDbXekHwm3zsm4t8ePrjgHrl2d5dTL62sApcsWoAcpmjD7v
         gMuEwUYgZFMnYzGrE9Z4Cvr9/N0BGZaXXbL9MIL6GYcI9QYilfqV2589JyhKhCj8iERZ
         NqJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=772vGqxA65bz16ef3P0OZqzhHKKFfpAXON1zFoQmwHM=;
        fh=t+dP9LGz0WIK0wpp1kONqWe2z/WC+P7shGtz7mzN4fA=;
        b=OJpiCA9I0Ocn4sEEuHUGPN4l5zPf1bs/TXmfSMhi/mXaMaw9bkTduMZ00LxR81Zi78
         T9swZFmjXrPQiDi69PLZ3b2sbHV0Dm1RF9y+Ez+oiYEqWP/ji3+u2h3z6lUJkynmn2rM
         x3Tm1d9kxDJHexH+0eDhU9P0AQGoFfYgUif0B+HFXHlQLoweNAxONbUTfSAVzAIje3AF
         7NEtmPU78AjhU2D8JBGVTkPpq9BGPj46wHU3XOSbGpqLkCpEeF3iOynMSY1dhJFaYxPk
         Iikz+dDFuYK5d2t3z2n9wnI/4f+5KKbv8yzIFkI/AlS+lmDPj8GkVIoHbCg3ClVExEmo
         nvTg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="X/RxlEh5";
       spf=pass (google.com: domain of sj@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=sj@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7450e32ae13si11644a34.3.2025.08.22.10.02.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Aug 2025 10:02:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of sj@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 64D49601E7;
	Fri, 22 Aug 2025 17:02:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E7EA9C4CEED;
	Fri, 22 Aug 2025 17:02:19 +0000 (UTC)
From: "'SeongJae Park' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: SeongJae Park <sj@kernel.org>,
	linux-kernel@vger.kernel.org,
	Huacai Chen <chenhuacai@kernel.org>,
	WANG Xuerui <kernel@xen0n.name>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Alexandre Ghiti <alex@ghiti.fr>,
	"David S. Miller" <davem@davemloft.net>,
	Andreas Larsson <andreas@gaisler.com>,
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
Subject: Re: [PATCH RFC 01/35] mm: stop making SPARSEMEM_VMEMMAP user-selectable
Date: Fri, 22 Aug 2025 10:02:17 -0700
Message-Id: <20250822170217.53169-1-sj@kernel.org>
X-Mailer: git-send-email 2.39.5
In-Reply-To: <20250821200701.1329277-2-david@redhat.com>
References: 
MIME-Version: 1.0
X-Original-Sender: sj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="X/RxlEh5";       spf=pass
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

On Thu, 21 Aug 2025 22:06:27 +0200 David Hildenbrand <david@redhat.com> wrote:

> In an ideal world, we wouldn't have to deal with SPARSEMEM without
> SPARSEMEM_VMEMMAP, but in particular for 32bit SPARSEMEM_VMEMMAP is
> considered too costly and consequently not supported.
> 
> However, if an architecture does support SPARSEMEM with
> SPARSEMEM_VMEMMAP, let's forbid the user to disable VMEMMAP: just
> like we already do for arm64, s390 and x86.
> 
> So if SPARSEMEM_VMEMMAP is supported, don't allow to use SPARSEMEM without
> SPARSEMEM_VMEMMAP.
> 
> This implies that the option to not use SPARSEMEM_VMEMMAP will now be
> gone for loongarch, powerpc, riscv and sparc. All architectures only
> enable SPARSEMEM_VMEMMAP with 64bit support, so there should not really
> be a big downside to using the VMEMMAP (quite the contrary).
> 
> This is a preparation for not supporting
> 
> (1) folio sizes that exceed a single memory section
> (2) CMA allocations of non-contiguous page ranges
> 
> in SPARSEMEM without SPARSEMEM_VMEMMAP configs, whereby we
> want to limit possible impact as much as possible (e.g., gigantic hugetlb
> page allocations suddenly fails).
> 
> Cc: Huacai Chen <chenhuacai@kernel.org>
> Cc: WANG Xuerui <kernel@xen0n.name>
> Cc: Madhavan Srinivasan <maddy@linux.ibm.com>
> Cc: Michael Ellerman <mpe@ellerman.id.au>
> Cc: Nicholas Piggin <npiggin@gmail.com>
> Cc: Christophe Leroy <christophe.leroy@csgroup.eu>
> Cc: Paul Walmsley <paul.walmsley@sifive.com>
> Cc: Palmer Dabbelt <palmer@dabbelt.com>
> Cc: Albert Ou <aou@eecs.berkeley.edu>
> Cc: Alexandre Ghiti <alex@ghiti.fr>
> Cc: "David S. Miller" <davem@davemloft.net>
> Cc: Andreas Larsson <andreas@gaisler.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>

Acked-by: SeongJae Park <sj@kernel.org>


Thanks,
SJ

[...]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250822170217.53169-1-sj%40kernel.org.
