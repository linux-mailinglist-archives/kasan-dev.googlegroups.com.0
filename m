Return-Path: <kasan-dev+bncBAABBSUVTTDQMGQE6YYSJLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 05B99BC70E2
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:07:24 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4df60ea7a1bsf14011241cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Oct 2025 18:07:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759972043; cv=pass;
        d=google.com; s=arc-20240605;
        b=IGujA6VMUW6Ag4ZIS9xMTGgOHp89aaShECxAUNFqLs6raJJyJnwLqFjNXXIkHOr2YX
         eN8q1iyhxPVL9uFJdIwZ5qU+m6cmt+HJEsa33GmVKfTFAP4sht/ohXyPeTdt//WiJjXF
         gs2HfOQMaj5GbsOtsOyQs2mrKoNrVpPQBl9yxzMuEu6wmaoABtmK2Gbtk0zzxwnUYU7x
         h0yVfGXc4geptQUCBmmKVVsxcii86hyrOFMpSCithkSUObTJVUid3CnOZ3sJeAiRZQnV
         vV1b9281e3CX2Fj96BzJbYbo1poGGu2eW64nQBsYeB3+Df/9plCHXf1akpd98hHZ0YE+
         Y9Cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:date:message-id:from:subject:mime-version:dkim-signature;
        bh=oWHXm5pOZ//WT3N7kh9Qd5oVfORVICxZ60B1gJjxYJ0=;
        fh=+MpZVR8t+MYl1qOGzAgrhW6XTMFjbUYnL0CKlaPrRTI=;
        b=PrbQ0W+8/DraXNK8m8QjnrL19ndFQfccJdG5WM7YMtiOQOUsBZlmafGdS9LT3DkZR8
         gLgP/T7+IbupqRkEinSpu9ZbfLVYlwz2Gq67vYfcdWDgvRV16B9+vz+Kjfr91QoVQAtA
         LzO7di6B/hReEcPl9p0cHnpDiNkHkZpX34OsAlv5RaF06rcu2k7YkykgXGcWkTWyecC+
         wtHJ/sW5+7bzo63J48KckKQ2GtWKUUcKvqmBO/ZfbOz4U/DUY+zy5oYPAjiFIPSKef+V
         PHEphAM4jz2qK5MnKf+Lp68sZvmI788L+Xj3b380qDFfSGrhjzCN0GZygaVxUO4IbhkV
         dwWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rIX5UnrQ;
       spf=pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759972043; x=1760576843; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:date:message-id:from:subject:mime-version
         :from:to:cc:subject:date:message-id:reply-to;
        bh=oWHXm5pOZ//WT3N7kh9Qd5oVfORVICxZ60B1gJjxYJ0=;
        b=ZUZ5Iv32Eyjx1A8tdG5N/+aDgoXQ47efd/GB3+vmcvKS28kqJZnO2jn35ng9MSV+Iu
         D0SEG7clymTKYXNAM9M9XtTdlVrT/1aV1hCyMRazZBEUkNoFEjxIzz/+t6rhe/kzDYr/
         EkAMLzaB6/VYlrY5jnOfGrspMw3nbAwGPEAQN0bPH2/o6sA82saTgjl94LVKCRmakhZ0
         Kp3TLnKwXK/nvPIrpoZPbtqOaSq2wO9hzbw0ZyJz1c/PsYsVBCBQmSzgHI93pNYeJuyi
         FHxMAEaZblwj+LoTb/YylJtzwlEIvn89l0iF8XzaBIjSfoi9pwwb/qwFZBvXrmsYQkVA
         1JXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759972043; x=1760576843;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:date:message-id:from:subject:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oWHXm5pOZ//WT3N7kh9Qd5oVfORVICxZ60B1gJjxYJ0=;
        b=rLkjuqXVgz/1zPBmw8YiaPvXKk/gBrQCaGPGCnM2XXKVfnzawBWMvv51sm8/Gr4hzR
         neBWurHocSRLavRfQ9cKJAl/TCQ/nZyczByzW1ZC33Mj5XQ01LOPWXcNPjqbtbMgIoHY
         4B5WiImj3t+c5ytVD7YvblyJb61wKVrZlYvcWrJL3BwuYSApZXDyG01x42ctQQ/W8aJo
         3tga7oOl3rC4u7AVyQ9eibnA78dMXPtTfqoM0DlMY5EOzFaACCOAxf8fC1Sf0W0Y3Km+
         z52xg3c8Y4hmUsypQYAI4Lc91YTSD181Y5LT8SxaqlhYPcoJiQArl0vKxORXi0pLxf3s
         r4ZA==
X-Forwarded-Encrypted: i=2; AJvYcCWFkyWGw6YSUI8bG+CXRg6m81wITtLycD+XiO60zQ/2jXZQ8ZFiG7+rYTYioiM+dvRoVkx50A==@lfdr.de
X-Gm-Message-State: AOJu0YyZlJTI95IAFmWmhu5yoFstM853r/zf5fmSXtde8Qe/Mk4mMm2p
	Jei7vDLpcsTg/kOMHOHh+mmeO/btQ9XBsPqzzkuTMXQ4iwIPh8ZsKweh
X-Google-Smtp-Source: AGHT+IFs2xkrGUN1JFuwKsbU8bK+VnTPei/pA/PDjNMp3QLcmnWy4VQb47cA4o9QPS2MoGrULAXt5A==
X-Received: by 2002:a05:622a:5914:b0:4d8:afdb:1277 with SMTP id d75a77b69052e-4e6ead4bc02mr88417951cf.38.1759972042823;
        Wed, 08 Oct 2025 18:07:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5u0a5VD2Cl+Uat5Voz/RAHom6P5JIyMxKQjEwlpbyJ/w=="
Received: by 2002:a05:622a:a6ce:b0:4b7:ad20:9381 with SMTP id
 d75a77b69052e-4e6f89c776dls6831231cf.0.-pod-prod-01-us; Wed, 08 Oct 2025
 18:07:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUG94+RzoFzGqqWkcBcAELqhH2l+uCYKsPffd4Bo0GccNSkDHqk5uFVW4d7ReBz+ZTLSDJERrzC21I=@googlegroups.com
X-Received: by 2002:a05:620a:29c4:b0:85f:40ef:4aad with SMTP id af79cd13be357-883509834cbmr906174285a.28.1759972041963;
        Wed, 08 Oct 2025 18:07:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759972041; cv=none;
        d=google.com; s=arc-20240605;
        b=hQt5OmJSQd7cwukGNOx6Ba69h/r8UySLNObipLZikCkXIqsavejCNHE0ai6uX7zoLf
         nsCCBErYwvk5hGTEm6xkOfsZEH58gY8M42NC1QXQxw33Jl4/cqnfHDTwrNF6BgViguzF
         miNF2ZaGSX79YZ046mRrAkwNEamuxmS896lWbaLzRtAIRSON+K7CfzGZo9mToODeUKMz
         yNGOmGN8Njn/TFN+j2NoknxrpHf+ZWnzYKoqHgijjiCU5qrDTYDW3pztIT0cwHQleFI6
         nlviZnNtIV5wdQrbYfu/uvNQB3iNx6adEXVkdJv++XAUZ9BdFv6G2IFYPnFd5aBdIuK7
         5piA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:date:message-id:from:subject
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=B2IWKdpLJh/9ubGaBFyA2jjGexkUAB88JLRjzbBWHEo=;
        fh=tGcYnW4TjvWygp0bXdZK2JxY7HeOROlRVoEEqk1N3+w=;
        b=ky6E6j7npDbgKkzxOZP7WA89gnvhXXKk8bUPaTsFVozvGrik+WClFNrHsdeYpC2ywv
         LfGmsHglHqQTUffMMykirpMu6Xg4t4X4ZX8ThDylvzj5/3Jzzxcxq17SY8eMCzLAcfwQ
         MMTzs3Qo3aZiS2LQJ1DGbWfXPE7gOks9dwT2pgDU+DMM2reXQ7+PsfSvC2v0VswDY/Xz
         fjFsAmRFrMzHASX12qrqXsTqeNtnzeOQ2zLXAXe/hWRFZFYYh0iwoF8qkMb8zuF5jxna
         ixcdGZX0NGAGVKsC384E8srGy/m72AMh3uBFb2fkeLu5IluqnoLXWaT9lG7c9VO5Vf0o
         U0Zw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=rIX5UnrQ;
       spf=pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4e6f90c408csi400221cf.5.2025.10.08.18.07.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 Oct 2025 18:07:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 34AA9451CB;
	Thu,  9 Oct 2025 01:07:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0EFE9C4CEE7;
	Thu,  9 Oct 2025 01:07:21 +0000 (UTC)
Received: from [10.30.226.235] (localhost [IPv6:::1])
	by aws-us-west-2-korg-oddjob-rhel9-1.codeaurora.org (Postfix) with ESMTP id ADDA93A41017;
	Thu,  9 Oct 2025 01:07:10 +0000 (UTC)
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
Subject: Re: update kernel-doc for MEMBLOCK_RSRV_NOINIT (was: Re: [PATCH RFC
 10/35] mm/hugetlb: cleanup hugetlb_folio_init_tail_vmemmap())
From: "patchwork-bot+linux-riscv via kasan-dev" <kasan-dev@googlegroups.com>
Message-Id: <175997202925.3661959.5694356441030280085.git-patchwork-notify@kernel.org>
Date: Thu, 09 Oct 2025 01:07:09 +0000
References: <aKyWIriZ1bmnIrBW@kernel.org>
In-Reply-To: <aKyWIriZ1bmnIrBW@kernel.org>
To: Mike Rapoport <rppt@kernel.org>
Cc: linux-riscv@lists.infradead.org, david@redhat.com, mpenttil@redhat.com,
 linux-kernel@vger.kernel.org, glider@google.com, akpm@linux-foundation.org,
 jackmanb@google.com, cl@gentwo.org, dennis@kernel.org, dvyukov@google.com,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org, jgg@nvidia.com,
 axboe@kernel.dk, hannes@cmpxchg.org, jhubbard@nvidia.com,
 kasan-dev@googlegroups.com, kvm@vger.kernel.org, Liam.Howlett@oracle.com,
 torvalds@linux-foundation.org, linux-arm-kernel@axis.com,
 linux-arm-kernel@lists.infradead.org, linux-crypto@vger.kernel.org,
 linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org,
 linux-s390@vger.kernel.org, linux-scsi@vger.kernel.org,
 lorenzo.stoakes@oracle.com, elver@google.com, m.szyprowski@samsung.com,
 mhocko@suse.com, muchun.song@linux.dev, netdev@vger.kernel.org,
 osalvador@suse.de, peterx@redhat.com, robin.murphy@arm.com,
 surenb@google.com, tj@kernel.org, virtualization@lists.linux.dev,
 vbabka@suse.cz, wireguard@lists.zx2c4.com, x86@kernel.org, ziy@nvidia.com
X-Original-Sender: patchwork-bot+linux-riscv@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=rIX5UnrQ;       spf=pass
 (google.com: domain of patchwork-bot+linux-riscv@kernel.org designates
 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=patchwork-bot+linux-riscv@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: patchwork-bot+linux-riscv@kernel.org
Reply-To: patchwork-bot+linux-riscv@kernel.org
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

Hello:

This patch was applied to riscv/linux.git (for-next)
by Mike Rapoport (Microsoft) <rppt@kernel.org>:

On Mon, 25 Aug 2025 19:58:10 +0300 you wrote:
> On Mon, Aug 25, 2025 at 06:23:48PM +0200, David Hildenbrand wrote:
> >
> > I don't quite understand the interaction with PG_Reserved and why anybody
> > using this function should care.
> >
> > So maybe you can rephrase in a way that is easier to digest, and rather
> > focuses on what callers of this function are supposed to do vs. have the
> > liberty of not doing?
> 
> [...]

Here is the summary with links:
  - update kernel-doc for MEMBLOCK_RSRV_NOINIT (was: Re: [PATCH RFC 10/35] mm/hugetlb: cleanup hugetlb_folio_init_tail_vmemmap())
    https://git.kernel.org/riscv/c/b3dcc9d1d806

You are awesome, thank you!
-- 
Deet-doot-dot, I am a bot.
https://korg.docs.kernel.org/patchwork/pwbot.html


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/175997202925.3661959.5694356441030280085.git-patchwork-notify%40kernel.org.
