Return-Path: <kasan-dev+bncBDCPL7WX3MKBBK5IU7FAMGQE5KEKCPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id DF254CD7740
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Dec 2025 00:28:44 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-88a2ea47fa5sf121255686d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Dec 2025 15:28:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766446123; cv=pass;
        d=google.com; s=arc-20240605;
        b=esriNR4iNOSnYisqKl2mCt4zA73i9wx3BW10p/eJRvkDEDCp1VxsmcAmnQGXsjBu2s
         3cp1vsQ91GVD6YY8xtHty1IEmCqoTzmcLnzeohr8yZGjzUDFdmMSCW6j3+MPTE1fS8RY
         OA7De6iIPxdPmy5P4BAnV96OxKl7RdsWwsMtM0FMz+TvPvMtg5TS2IvOoskZsT5y68UW
         2k7FFeB7+Ey6929ivjUGT+DnfqAlbalgTBgCY+l8K+ooq6j9fFdzF/cAkieSRxmEAs6x
         6o9WiYdylPcCs75MnXqiAIRPCoUNdo5G32NOAayuuO8ylBK6kwByFhT4VzMooqn4ac2t
         BAMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=r+FEPPn3wAGZoLbwjakgYq2qQvgaV1/mAtQJ06DipwY=;
        fh=YRaJ1FRIVSR9xSpDtBn2jYkIsUXcsT8f51Bbz09YiyA=;
        b=a3bXKerjQXJxNfye7XV/7fe+NyDrQHOAaVKTCwi59bbF1b8ya9KErJqsjtsFM+lrjU
         2n2bpgofv6LQ0P+AWCHwWq4tzF2s1KNS4gwlYEWV4Z1fK9aYQKMwWqwoBoXDaI2945oM
         BnzCo2dnJ6JsNfRUYh2rYpkVIis832T9mPLTHZE2NuAM2A54bdqfrrDov0hfgwFEM9bw
         Soi5caXPteKhfEZs7ltPq2NT0lq1H7YsHzD/25tMi8Pw/2fNO1KEevpk3enokXF5Xknp
         x9KgZJgik595SuK8C7+j2yRbbx7FC12hqyv7GqFoJR8Oh8FkD0ccUUtxCARhdiVRULi8
         6ehw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LFtXiYEe;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766446123; x=1767050923; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=r+FEPPn3wAGZoLbwjakgYq2qQvgaV1/mAtQJ06DipwY=;
        b=dhxfd8QvnNfX3wRn+Epgddi8/TahU1jW6dnABd57B6968EOpbsqm875g6EPwyq9X5v
         J7GIsgT9haFx3Anc6dF2TN1of0Npr13B0/3t4ox69XeAZLzK3Z4xX5w4QBh0gj0M+pZe
         ULl2NmDRu1M5gc7IW5bY732h4xtwHNntrvUetbewTSIkQPKvnb8sO+SIMiW4TWFX4tuJ
         5i/YinQNDRYvlVPmsTLXSTEJO6wI9+4xxJjrG9lYl6j1tHDpdzyIDZP4e8WfMHH8KKAW
         Jx4yWDFpALI4U9SheODHMwpq8+MIKq8TBv/KylITWBG7P8JHIT3l2eadOtN/Drh1/TN1
         d3Ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766446123; x=1767050923;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=r+FEPPn3wAGZoLbwjakgYq2qQvgaV1/mAtQJ06DipwY=;
        b=Sny5raHbJofN21xSfMMJUgLnlsuILkmRVHaJusrwbkixm/11sO3lJkWX/P+iZr+Kk7
         VfKb1OrOrWCKsapCB+pa7qYKScG6LmN4HfntluA1O2oHHmHreN1xmCnc3p26eN7F0xho
         BNZ5p7lNK93gt7oQ7e1FwmU29F2OvGFI5iK6jyR4Ijja1mslJV1RSlBR7rvIG7MQCg3c
         xT7fSiXAtJCpVvQytPEujzhAaNTqmO99HXclDD+kZFQjp/sZwqj3huIQhuekvJBWGO2P
         1TJcfPStrzSrwOFGm+1i3rbvqVO4myVyd/ojdlcy10i5OgYCqblLfV7leEgSGBRItCTr
         gtqw==
X-Forwarded-Encrypted: i=2; AJvYcCVhxH7LoegYw3SNxpppsy9JUQbQ85KdXcI9aI+/s/IdLUFisRBVhpatQ97HaEtrNhhicK4nzw==@lfdr.de
X-Gm-Message-State: AOJu0YzEaQYmZr3Q8UmZc3EaP/4LmWIBRlzD9aPi62+CK4X3klumx3uA
	5RuPAEDbYNONJCXMXUi579otIwjvkYTeXV3wKvYl7QquxVyzC0IW9PPb
X-Google-Smtp-Source: AGHT+IH2EVsb6qhR9/jrMKbuObxxt4L8NS48rjkhEnF88D5vWkUCNTDKq+Ngvnx7OnB+bVXiIQbMoA==
X-Received: by 2002:a05:6214:301d:b0:88a:3c88:d0fd with SMTP id 6a1803df08f44-88c5204affamr287670156d6.21.1766446123340;
        Mon, 22 Dec 2025 15:28:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZkUIH5PqVP03c7kkv1xuY5uE3OM0+iQOEuvfVYGfBd+A=="
Received: by 2002:a05:6214:1049:b0:880:5222:360 with SMTP id
 6a1803df08f44-8887cd38ed5ls97672486d6.1.-pod-prod-00-us-canary; Mon, 22 Dec
 2025 15:28:42 -0800 (PST)
X-Received: by 2002:a05:6122:3197:b0:557:c734:ee5 with SMTP id 71dfb90a1353d-5615b8a7c5cmr4301216e0c.8.1766446122504;
        Mon, 22 Dec 2025 15:28:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766446122; cv=none;
        d=google.com; s=arc-20240605;
        b=Y2wzrYVW7nLxmUoZNDCcCnDXsgXqR5Yxjm5Upp6hCPQpz20Xo8q9Xqa2L7Pu5PL3bD
         dPZI/HrsJilPRAeBN4i2gyXa0O3dfEqhjh6ci0FlHw9KAFtnh7I5WamG3SiJquPgUAkj
         0AzdcQtah1H5kRZLopKd8kSo4Ea032u/UuBB26Fnf9wKqSafMoofNZINzptD3oRt9s21
         maYgzXikI5+XP1y/rtYVWNPkjPFkO6neAWmpkGqb5RopNLzHvBr2W/gUzwc6rfxwnAeG
         Zr1ZhR271Wjgn5UE1fmLcq7v2M75Uw2jm0rUaAd+8+bTqcsJd2E9Cn91ObPUerdv+HtV
         5lqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=CzlALd2WwcLw5GnFD7KeU5MZ8lMNb+L9pXcp83mGNIU=;
        fh=5Jcl65QtvmOMu16V3b6mb+3gZgsX7agMi0DhxAwapmQ=;
        b=Jf2TcoXOzQ8ohaC95ByPztpvs3sXcMOdv7IvfAukzBzwbkIhheuFuVreaGa0w09dX1
         8Cez6XqulJSr5hisCwxkw4RYa+cCNmmi62rFwl3ls519vipoH+Yk4YW8/lpyhOB8e32L
         w9a6n1R8tH2rIgqsazdyZ0pm+TXm1LHQ3+ODJuIGIBx5t4hkcjRK4c0bXjbK9nPQgY6y
         6ezKXKzs8iIVjtTuFxbdQp3I3pPBKtUWFB8MPGqlLw/slBg9ZhArHzMKNzuVs8omC6vA
         Dh3ceI0iCdF5aqKDD2qAls1+MFvRaz2Q9ArFwlfrgIZrONZg6ubtIsnMAhfQOOTAvJcm
         Q1Nw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LFtXiYEe;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5615d225328si319042e0c.5.2025.12.22.15.28.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Dec 2025 15:28:42 -0800 (PST)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 8BDA660136;
	Mon, 22 Dec 2025 23:28:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 40145C4CEF1;
	Mon, 22 Dec 2025 23:28:41 +0000 (UTC)
Date: Mon, 22 Dec 2025 15:28:40 -0800
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Randy Dunlap <rdunlap@infradead.org>
Cc: kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org
Subject: Re: UBSAN: array-index-out-of-bounds
Message-ID: <202512221526.451D1BE1B@keescook>
References: <90e419ad-4036-4669-a4cc-8ce5d29e464b@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <90e419ad-4036-4669-a4cc-8ce5d29e464b@infradead.org>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=LFtXiYEe;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Fri, Dec 19, 2025 at 08:20:13PM -0800, Randy Dunlap wrote:
> 
> from kernel bugzilla:
> https://bugzilla.kernel.org/show_bug.cgi?id=220823
> 
> 
> Dec 15 22:01:52 orpheus kernel: UBSAN: array-index-out-of-bounds in /var/tmp/portage/sys-kernel/gentoo-kernel-6.18.1/work/linux-6.18/drivers/mtd/devices/mtd_intel_dg.c:750:15
> 
> 
> (from drivers/mtd/devices/mtd_intel_dg.c:)
> 
> 	nvm = kzalloc(struct_size(nvm, regions, nregions), GFP_KERNEL);

Yes, this needs to be immediately followed with:

	nvm->nregions = nregions;

> ...
> 
> 	for (n = 0, i = 0; i < INTEL_DG_NVM_REGIONS; i++) {
> 		if (!invm->regions[i].name)
> 			continue;
> 
> 		char *name = kasprintf(GFP_KERNEL, "%s.%s",
> 				       dev_name(&aux_dev->dev), invm->regions[i].name);
> 		if (!name)
> 			continue;
> 750:		nvm->regions[n].name = name;
> 		nvm->regions[n].id = i;
> 		n++;
> 	}
> 	nvm->nregions = n;
> 
> 
> regions is a flexible array in struct intel_dg_nvm *nvm; [see below]
> regions is counted_by nvm->nregions.

Now, will nregions change again after this point? There is a question of
whether nvm->nregions represents the _allocation_ size or the _valid_
size. It seems like a max is allocated but then only populated up to a
certain point?

> Question: does UBSAN use the value of the counted_by variable for array bounds
> checking?

Yes.

> If so, that means nvm->nregions must be updated before the array entry
> is used. Is that correct?

Yes.

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202512221526.451D1BE1B%40keescook.
