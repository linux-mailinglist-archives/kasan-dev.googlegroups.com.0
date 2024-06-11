Return-Path: <kasan-dev+bncBCT4XGV33UIBBLWOUKZQMGQEC2KAFSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 821F29044EB
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 21:36:16 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-6fc395e8808sf5262548b3a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 12:36:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718134575; cv=pass;
        d=google.com; s=arc-20160816;
        b=lxgQ2SUzVN05PRB/kaGcHCXKAo8EUSG2CgpDQ9xafmIPp7TLuGCLBHQn7OaC75Ej8Z
         Ik1Sk8O/Ya6HVqs0qzJF6vGPtdf5p16SSH8zwwRf1KkWKUj13kr+Q/amMP+0IXMfqDOR
         AMZWT2J2M4J4LSFmYaX2qW0mLWCecaJDMcOxPn73Ol5z1E3EDrcOJHrnudsRHwyNmFhb
         Jye/hNuWYHdy01rKkeoZ5XTBcQ3qKV4z6PcFeeipCB1oxXVjbSh70h83PRsUid+OqL5e
         cJpZnjH/KfpQZ5psmbVz8hAZ5lP/OTLDE5n0joa7UNJbV5t7nE8QXw4sfsKAKv0bwnlv
         trog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=sqTAhA6M6zJjDLc7IDGlFjlhI7NFj2K9ziEbez9rVqQ=;
        fh=wZo++9nsNkyrc9gMn7o6AEvKEiBc1ICIt0nWThia4rM=;
        b=t0pWS2X8FYVwzpH/niycyXYVFKwqNtfptfb7wLWwNgpDefF3TBUFEF+xwZjLO9Se3t
         c9Lt+wVv5tXz+StF8hsLwWK9g+kvGYWyGMKbblv27IgeoaGIzcR2LybqodOikORjU2K1
         SRwmwp8WRcWuxn0L1AIJJsjG66pz1twBkjLfYmqoV2ANBuj37xs1BM9hVzyZGSoDixOu
         21mWkequbTPjUz64KQ1LoBMHGRgsTIqrTy/eGVQJPCczGMlxzU4Fwz6R9TXaAoRbGr0u
         Fy/aoRoVB7gZfZJjN7j+qgBwx+Jm/A4daFvntJ5+WJJa53sXbEpiyNYryqf/eg91N1uE
         FMjA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=JB948CVY;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718134575; x=1718739375; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sqTAhA6M6zJjDLc7IDGlFjlhI7NFj2K9ziEbez9rVqQ=;
        b=Mipf6y+htCghpOSfI0OxnENge35Z97DPwYuy0kW3Qc+87D7cTGMn9br8vgL2UNKF7G
         xoYN49KVUaJGfJveaGZaTEkcIir8EUc+VjMGZ50rhdaQYsT2tB3EbtCnSL0T+QioH1PY
         ZG907+4vlzlvzw82h0Ccn/hxCf4F/WLWR6+L0Vfr+BBwpUdnMca+wsOj1k73UGghj+3V
         o0f4EyS7pVN6wP8Fnx/ItXkOebQtCY7vCur7nIzpzOAm2dr6FfkTPr/p6Yyvkk87Y8oh
         YyrSBCE/fFQA3YNuXQrbdUp74zyUgsISy83ZG23QrFWUpg35nDIxaROCX8gr4NRQInJ5
         RfoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718134575; x=1718739375;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sqTAhA6M6zJjDLc7IDGlFjlhI7NFj2K9ziEbez9rVqQ=;
        b=psKNFG3vU464GuN6PziVsQ4Y1r7jbuZzwwjjIvgFss+9HNvSRgC/IdGb5K+wiyivta
         0C/I/4LehNRXlGDpAznK2rN9lKKmTt6qq+mW6a9qBLb4GrmlOAOUR47kAaBepaJv/lLD
         MeQAxqQsSvhP563u//oO343Kk1avv94rE5tFoIc1PJoW3WHmN4pnVZssEmb/wgJwi2Nh
         uXfdeARme6s/lBIl3HHXioqOmvxWKiv1yQi3ugnPzmI1yDA2f0R308gGrRvp3JdVWcm1
         680JkT88siwd5DLFLG3qIA0qDaJQavRATr1OVKr7x91pYMe+AAtD+mvFt7h08d2+zSpj
         mMCw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUUFPCv/v6clTFwGZGWmEM7Wuwb72Opk/WemP4BKw4DDQeWhbZgEkDXAM9qkd9DrS/SQJhfRlNN3+NCbbr45oLC2GdYVjfXpQ==
X-Gm-Message-State: AOJu0YwW60P83QZ7eO+M+unAk7B76HhnanFo4UghU1XkGYuuOnEpyOTZ
	kKgawBLlLi+kOE9ZETNPT91WyWRgduft8FQC6SQ15GUHF2KuZ8CG
X-Google-Smtp-Source: AGHT+IENFriCshCANA9mRb+VmjLvNIu9s0b+acOZRALmV21jB6DKHUhtWk5BTrKPk7NeybHhO0HstA==
X-Received: by 2002:a05:6a00:6903:b0:704:13f6:6866 with SMTP id d2e1a72fcca58-70413f6bea1mr8824795b3a.25.1718134575005;
        Tue, 11 Jun 2024 12:36:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2d10:b0:704:2cb3:ab06 with SMTP id
 d2e1a72fcca58-7042cb3aba0ls1818433b3a.2.-pod-prod-05-us; Tue, 11 Jun 2024
 12:36:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXgeqoIuLP41JB0Hu1HjnD862bBg+th6nrxXpxbYGfFxzK+HBbDMCIZa1pQkSldYIpuUdvz3lgj+GhGU1DdYyPWEzGsHByPCnfDWg==
X-Received: by 2002:a05:6a20:8410:b0:1b0:14a0:c875 with SMTP id adf61e73a8af0-1b2f96d6d58mr14526839637.1.1718134573565;
        Tue, 11 Jun 2024 12:36:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718134573; cv=none;
        d=google.com; s=arc-20160816;
        b=x2dSzUFurWYFshsxkt81NSW6Yo12aE1JPmFDBTqkGZxI+OWBRfKBdcb7urYzzAmjaP
         Ify6A34bDpQ1k8ZWTjKjrV6BQ4BkfVlHNWMqkrMXaAeRTiGUOAjnj8VfYc3C1E2fOZVn
         LneHXswkex3PQgdal//y8nzaC31XI3ulNl/AcTsALN9UX5pGjvvjnblq6tmNapUKXOWR
         ZVHQGrp37GImrnPPzIeESnjoAzY5MV8HQlOL4am6xl/l7zLaU5Oo/RaHaS/1O6CH3sY0
         ldC1fHZxG+kuv+6nIcYnwEl+93nZXQYVghOFbfk3bGzNewSTGDFFpzQ5LWGUOFIRxsef
         FiOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=BKSoQBeqyVLDXP1a0GwgL1NP6+fOBxoLMJmMe1bwmyI=;
        fh=H6CH34hcYenSB7FXrgY3SiQWBl/4Errpy/cWaxiK6f8=;
        b=x+01Q3yta9oHnJoVzOdmVCrfemMjozkvaTBf4s2zeYdFKHFs+PseaZO9rLdwlHkE+R
         AU9u25ClRK6vTDRgsA5ftGaVUUaZdmCmJrNHgR2l7vlugH/G2sAFfyDol47ZewRHTl/H
         cPxxQBIerYynXG/aN8+v/a9q7/1sLzIP6Rq6SA/QAYbq8Z1v4WS47yPAK/Htl+6XEM9C
         2rAxqcpJv+0N8ygmF4N9L4J+nO/CDo1naxtfWE1Zglo0Un8gRreDieI1AX3bYgt58iXb
         kbPtwgMwWhwmEr9g6mROho7FWRdt6yczrGj+STgFulcDstpKTOyJu7ojZw2ECz6dk2C8
         noRw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=JB948CVY;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c2df95ab5fsi496232a91.3.2024.06.11.12.36.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Jun 2024 12:36:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id C5D446117E;
	Tue, 11 Jun 2024 19:36:12 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C5183C2BD10;
	Tue, 11 Jun 2024 19:36:11 +0000 (UTC)
Date: Tue, 11 Jun 2024 12:36:11 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-hyperv@vger.kernel.org, virtualization@lists.linux.dev,
 xen-devel@lists.xenproject.org, kasan-dev@googlegroups.com, Mike Rapoport
 <rppt@kernel.org>, Oscar Salvador <osalvador@suse.de>, "K. Y. Srinivasan"
 <kys@microsoft.com>, Haiyang Zhang <haiyangz@microsoft.com>, Wei Liu
 <wei.liu@kernel.org>, Dexuan Cui <decui@microsoft.com>,
 "Michael S. Tsirkin" <mst@redhat.com>, Jason Wang <jasowang@redhat.com>,
 Xuan Zhuo <xuanzhuo@linux.alibaba.com>, Eugenio =?ISO-8859-1?Q?P=E9rez?=
 <eperezma@redhat.com>, Juergen Gross <jgross@suse.com>, Stefano Stabellini
 <sstabellini@kernel.org>, Oleksandr Tyshchenko
 <oleksandr_tyshchenko@epam.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v1 2/3] mm/memory_hotplug: initialize memmap of
 !ZONE_DEVICE with PageOffline() instead of PageReserved()
Message-Id: <20240611123611.36d0633c65ec8171152fe803@linux-foundation.org>
In-Reply-To: <824c319a-530e-4153-80f5-20e2c463fa81@redhat.com>
References: <20240607090939.89524-1-david@redhat.com>
	<20240607090939.89524-3-david@redhat.com>
	<824c319a-530e-4153-80f5-20e2c463fa81@redhat.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=JB948CVY;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 11 Jun 2024 11:42:56 +0200 David Hildenbrand <david@redhat.com> wrote:

> > We'll leave the ZONE_DEVICE case alone for now.
> > 
> 
> @Andrew, can we add here:
> 
> "Note that self-hosted vmemmap pages will no longer be marked as 
> reserved. This matches ordinary vmemmap pages allocated from the buddy 
> during memory hotplug. Now, really only vmemmap pages allocated from 
> memblock during early boot will be marked reserved. Existing 
> PageReserved() checks seem to be handling all relevant cases correctly 
> even after this change."

Done, thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240611123611.36d0633c65ec8171152fe803%40linux-foundation.org.
