Return-Path: <kasan-dev+bncBCY6ZYHFGUIOJ5FMSADBUBBRW4HFG@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4120F4B62B5
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Feb 2022 06:30:13 +0100 (CET)
Received: by mail-ua1-x93e.google.com with SMTP id h19-20020ab06193000000b0033cb73af2ffsf7560247uan.9
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Feb 2022 21:30:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644903012; cv=pass;
        d=google.com; s=arc-20160816;
        b=TRY8+I1Iu+kM4uPu6NAyYgfbd0sPpktF8rg+KPhf1DfIXBE1N+ZFNCCfICpSouWegF
         bjJNXwKRKISanaxNmAF26hvp4s0FQJO/CI0xicc3jwMY2eZUgvXEsJW6Ltt/h11taYjE
         rix+kC9HFDrIH8VuWpjxSKKLVfsyPASildnNpENNz0UyVSbwQrlGsw8Bf/80OdSRbdwu
         dKKPzqI0lhvzEG22tf3Kv6fF2JlM7h+HXAzEp2oReBbPXfYg93Dti8yY6gTJCSy9xb6V
         pnULtoQe7MYfNT3W32raSRmzesBNcTym/MURpmPEjnJEuedj5DlwPHg4pCfJKCIoX7no
         Pyrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:date:message-id
         :subject:references:in-reply-to:to:from:sender:dkim-signature;
        bh=075sFSsF0r05iN3BI4lR0DOSgovseNNTXHOPxD7zrWA=;
        b=rePZUO0VfY5FBo7GxHB6DmAFLdovcBXO0pBVvtRR639ipsuCX636ITWpHyf5GLKzHK
         Iy9I7sk08dDe7Ps2HCASTY/k1D6oy87r8duCoYwxHhWS343PyBjoBkYiBVYaxvUedHkn
         nxUpDHXtdBETgPmeB24U9x8zmQtKp2YzrIVw9db3jlUaxEfS+Hdhf8+wCbt4VOJyRVfp
         MSG5qNchoDncu8bXlOs+lFyfYwTIjfbAELtVqerXFzv+CUwADJNVr1pI9ecOhQBxRj32
         GEQNM7XOWbNv18B365hNL+R1HTyyWaUTb+aVuFrQDgkTSikob2pazL/igY029JzhmqoE
         8azA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of michael@ellerman.id.au designates 150.107.74.76 as permitted sender) smtp.mailfrom=michael@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:in-reply-to:references:subject:message-id:date
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=075sFSsF0r05iN3BI4lR0DOSgovseNNTXHOPxD7zrWA=;
        b=mc8b+X3dwwaVnmwwsUEY1bgutrRJGQhhJf1bx0Mj136UpdCAxFG2slPjs5mM4lDBVQ
         bHIj5JN02ibMKs22BJPM+vuIcwLhNPREJPALDxxBNIrqKeq2V9iASnUoN1Waiqb8xzeO
         nXbkZJbXIV9hwCXjWoyWG4X3Ni1/vebG+7Coo1/oqt3PhCzIEO1XVuYMYKnaBvvV8Jvq
         gK/C7Mv/9mo7nw2oY6n3vkSUbqxruADFy5wVVodAjE4LHNpAcKpK/YTXwzpSiJWt7dNI
         sUcJSUUMg+nFNUunBYW7WZiwXoayKEbwSVHYcvnw83DCVivdUDr1hY0392LbDmAWQns0
         VUWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:in-reply-to:references:subject
         :message-id:date:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=075sFSsF0r05iN3BI4lR0DOSgovseNNTXHOPxD7zrWA=;
        b=thhvu3fksv5wRvSSnEhF3ccWCP9EFg2ZZryzGnjWDxiP22Wsts0dZRwf5FKdlMlXjz
         4FsfGekRdnP5SS5PKBjX96PxlWHw3LvaN1OelZlmgPiAR1thT+EgmS3RUTy4QdCPR2NE
         btk5brQdpt3g5KEsivfv2Mmiay54TAz5xboQMEURmzA8TzJhX1BnJ376ptERpjngmh+O
         k0GijPLu2+nuTV+eRQIriZP22drTo0jLYxnpnrZyp7rmhrdn4A2v9C8uHqTkbxTVMX5H
         ivlUkciSMYyFtIZe4grUtR9jgicT6Ae7Rs8+hCUJHCrmPzUXLtzXQTWaV+kl57kGhtKH
         ++sA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531gXhRdWWxbaKQjUh4GI3gnwoItlZTcGCHirWHHtZs6yd1DAd5r
	vH82fpVs/LrWZD0svPaP48w=
X-Google-Smtp-Source: ABdhPJwgO5sL2JG/srmFZTOKxznNfCmobq0WyrQMqcvXFI13cf4LsLi/kZbzA/r+THP0EiJi+Y57Ow==
X-Received: by 2002:ab0:3d98:: with SMTP id l24mr1000507uac.13.1644903012174;
        Mon, 14 Feb 2022 21:30:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:cc1b:: with SMTP id q27ls349829vsl.3.gmail; Mon, 14 Feb
 2022 21:30:11 -0800 (PST)
X-Received: by 2002:a05:6102:3712:: with SMTP id s18mr848732vst.23.1644903011645;
        Mon, 14 Feb 2022 21:30:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644903011; cv=none;
        d=google.com; s=arc-20160816;
        b=fuq6zqHKCTvqbf2gP8/83VlYuVj26HBjXsb+qQ8KwAY3p2AT0L8fcjoSRvbFlV9BMj
         vxGToCCx8KJgzecsr9w/cVM9F9MRaQ1l4OeTlTVFxUgp45sDV9verwDyXh9n71qpIZEP
         zOgTYHP1pF1ej0ylt7SCAPAcKxmbZaHMnDjNHMf3anuGrDF4A3U4wjyQmshTgyMf0Qnj
         Juom8/S/dxMZ5sQyVy8OKbbNAi8g1INcbaI/euvdBhcPk+c36fFs8Wo1qSTaxV8Hrvze
         iXuWCnPP13ITOI1zSQ8r+dzfiCWoNmAA3HH1o+sFmv3jKLvtABD6Pk7WvJ3QSNCTNptA
         HcXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:date:message-id:subject
         :references:in-reply-to:to:from;
        bh=VHAMcvtSat6SBjziPayV4E8pNM6BNY2NEhuRmpxU0fg=;
        b=NIDq9qm/4+wNHgDddjBedDivxnYS39qyPZrtqviolFTU6J8AxtZj0JLzfZIWkGT3JG
         WvHhv3RDnAGAxCUd4A+QafmIc225n5I4fv+43iODQRwHnKpseROTI+yaX0Vz1BDY2sKk
         WfP3N84tt9/Xn+DlJNoZ337+Kt/Nvx75IuwDWglXzX8gssmT4Yw3kZuvkc3MpjO0DjV1
         BxwkaI7ZxQClbgKW7+ZwEv3SY3i7ce6IszqDwglcUh0SPSGqtWOa6dCfNNJt84CdvmbO
         8FpiNMpTWZqZBQWxHU5Ufowcql5F2gFqvVBlmYZ9T7PqICrUCVVksBgWp6g9/HdetjdG
         MBHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of michael@ellerman.id.au designates 150.107.74.76 as permitted sender) smtp.mailfrom=michael@ellerman.id.au
Received: from gandalf.ozlabs.org (gandalf.ozlabs.org. [150.107.74.76])
        by gmr-mx.google.com with ESMTPS id az37si2923395uab.1.2022.02.14.21.30.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Feb 2022 21:30:10 -0800 (PST)
Received-SPF: pass (google.com: domain of michael@ellerman.id.au designates 150.107.74.76 as permitted sender) client-ip=150.107.74.76;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4JyV6454LFz4y3t;
	Tue, 15 Feb 2022 16:30:04 +1100 (AEDT)
From: Michael Ellerman <patch-notifications@ellerman.id.au>
To: Benjamin Herrenschmidt <benh@kernel.crashing.org>, Chen Jingwen <chenjingwen6@huawei.com>, kasan-dev <kasan-dev@googlegroups.com>, linuxppc-dev@lists.ozlabs.org, Michael Ellerman <mpe@ellerman.id.au>, Paul Mackerras <paulus@samba.org>, linux-kernel@vger.kernel.org, Christophe Leroy <christophe.leroy@c-s.fr>
In-Reply-To: <20211229035226.59159-1-chenjingwen6@huawei.com>
References: <20211229035226.59159-1-chenjingwen6@huawei.com>
Subject: Re: [PATCH] powerpc/kasan: Fix early region not updated correctly
Message-Id: <164490280217.270256.12753879562641501185.b4-ty@ellerman.id.au>
Date: Tue, 15 Feb 2022 16:26:42 +1100
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: michael@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of michael@ellerman.id.au designates 150.107.74.76 as
 permitted sender) smtp.mailfrom=michael@ellerman.id.au
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

On Wed, 29 Dec 2021 11:52:26 +0800, Chen Jingwen wrote:
> The shadow's page table is not updated when PTE_RPN_SHIFT is 24
> and PAGE_SHIFT is 12. It not only causes false positives but
> also false negative as shown the following text.
> 
> Fix it by bringing the logic of kasan_early_shadow_page_entry here.
> 
> 1. False Positive:
> ==================================================================
> BUG: KASAN: vmalloc-out-of-bounds in pcpu_alloc+0x508/0xa50
> Write of size 16 at addr f57f3be0 by task swapper/0/1
> 
> [...]

Applied to powerpc/next.

[1/1] powerpc/kasan: Fix early region not updated correctly
      https://git.kernel.org/powerpc/c/dd75080aa8409ce10d50fb58981c6b59bf8707d3

cheers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/164490280217.270256.12753879562641501185.b4-ty%40ellerman.id.au.
