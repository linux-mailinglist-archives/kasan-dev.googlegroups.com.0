Return-Path: <kasan-dev+bncBCR5PSMFZYORBH7V4GBAMGQE32HHRQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 89187343EFF
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 12:08:16 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id t18sf26702138plr.15
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 04:08:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616411295; cv=pass;
        d=google.com; s=arc-20160816;
        b=ycdHtiZVXPfnamHnVwkMgItzIp+5c6JVJsRQr95P+egkGtQF59VSXEMsFHlr6mVkgi
         fH/uD7dfb0P6R+zlDmtFhg5fpecE0kd/LyDmz1VKc94eKR7nH1mTo4rJGC1bjEZLwxXu
         e79g01niJukCbhTS2/ZJoXYA8YbHM3sF/w72U2EBVWdZmvDTTwiZTjNtGMLwuy0RHC4q
         sRTPa1PUSEOoB8q8Pb4tkMsLuN4SBzFAvPcNeDEi36jd+q+NJsMqX7IsGjFaCgIzUrIo
         v49mAYsHSvhd+2Tewb/Rsydh+5fkg9Sjy6LnwY5dPZsl+sys7kvlnWeuRQ3nmtl8AbGd
         sz2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=Oqe3EBKlHmdKFFXYx+6ZRZW6vMC14ueYj65fWxanKkk=;
        b=qJsvKjgjaUb8KEvnueq2dd9bEoKJHpHCqzy5aaOjpwR2VtFsnCTxIE240wpTkoZ1y+
         ViP4LaoUia1ZeLB3vyOMPjnXGu8/t70LU937VUB8VU9sEy4BVfJgCsuwuattMiryVBzg
         n1ZONsXPCZFgWbXyLzG/DGD1545Ds2u03Dl9a/kGGfgO9E5sTZtentuZ9ziyU4JsJel4
         ioVZJWeswjhX9QYnyb2sav53AImSowPwh8jHEPBnOcx874M9IiJadpKSvfCq5kFhFxFS
         pPynDCz4+4fmli8wlPRzbxWRzXR7y4Ow8f0ya3kWKJNvpnBt2V29dv28r3BkhMjkY+5h
         AWGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b="cFUGRWY/";
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Oqe3EBKlHmdKFFXYx+6ZRZW6vMC14ueYj65fWxanKkk=;
        b=M1NGJOYQpF1cRagYsPvKd3xwIxHR32fR2oXqLdvbBlW0i94phRgPSEBFoJE/4gwwca
         JpOHIEIimUDRSjsJRjPsGuGk/I0UnOwYPMk4shZ/kBTLeE3rBnpH5tKWLUR0Ft2zS9LH
         8X8R9jQiaSEW+XlUKS7A7qmgH2YmXlBxAp+tTUAk1ZGnKWcxR4gff6oXfwo/PD2yqHSz
         /4HptWmdYsRpoPWXXu9DoBgefRZyvjev9ijzY1vbrtLw+VpMMB9cBCP/EurBVtjKaOWW
         KZDRJU/fsqVK/IySPsLRbSs0s7FezNsH3mWmFsWKCKb2Ydao7SCdHLpLEOjgVECYmtyr
         R0fQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Oqe3EBKlHmdKFFXYx+6ZRZW6vMC14ueYj65fWxanKkk=;
        b=DrzHpP9C6kKVLB6DedlRoaAdTRxjlYEu1Rtk7Pwd5Ge2vcUm2QymWa33+b0Q/Xthog
         stdNncRDxzxuHcPZjV4H8B6m6ao6Hu/b2rct3qVbFU7SKXl2XWHayNQJPGuPi0OZF+Jj
         Jw1nBqu3JLHR+tehEaecpRiWA+DMqEr5/v+CZQG9bNyg8U99hjPL5aS9/Az8wenSU7JB
         KZiqUSKJxBdnV149Iz/FPl0ArhtkpjNAdwy83kEkzzuxYpgYRUBoX0yulAfL64W/ire1
         rQgQF9SX1a8Ps0Ghfhu1B+RM3mkDZJiwKh61Gn+q0UKfbk2VCMV8b+AcaZ7xVSo3NJhc
         sR9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530wdCwTS2WGPUfAl/+F/1rUhzso3uhtGhYqOJYhLlWMEtEY2qja
	P8JKcv0FqHcZZ1shbv7MM/w=
X-Google-Smtp-Source: ABdhPJxwLOKm1Pbm1VNk67u7eDy9VWvtQmBwVzb1QeDXB3OXJomo05i0EZ0W39UJ+9MGyOXlcsHvbg==
X-Received: by 2002:a17:902:7612:b029:e5:f0dd:8667 with SMTP id k18-20020a1709027612b02900e5f0dd8667mr26544355pll.59.1616411295290;
        Mon, 22 Mar 2021 04:08:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:e845:: with SMTP id a5ls422765pgk.9.gmail; Mon, 22 Mar
 2021 04:08:14 -0700 (PDT)
X-Received: by 2002:a63:5c07:: with SMTP id q7mr22229227pgb.52.1616411294718;
        Mon, 22 Mar 2021 04:08:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616411294; cv=none;
        d=google.com; s=arc-20160816;
        b=aSOHV3D+fyffPN7wrbUWMvyd/JE26rxEV3gl8uquOLgmVsox8PLBjk0pNNI83XxZtr
         QY7HMUKLQqy4bQ2pnj69bL3vbgw+KfK8DKi4D8R2ljXBaBN1Pd+ioy2oIZl13ojlbTU4
         A3EkuyEa1DG7h0uAfhDnpWoj2rymVSctEFK7eqCikJGJVPFL26bgtr8i6X4kq0IckHA+
         GUbxjW/2mTYFqqLK/JPypTCvoseDDHxCEPfEl/74r+lHrvZI9yz/do8Pue8rAMiJeYLT
         06f2q/FVF8bF7OhDPUSEkI18JVi4KKNOKPp75u4ImduvzdLMKO94S91U+u1MX7Qs8s0Y
         Mznw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=+2XTKTwZgGzwGroNR0nyoNXpyJs9IcBCTbMZ8ftwtOg=;
        b=eUd1YflHc28zgKHk1sPYEdbnb031XVYBLM0kDCqLjvM1CGa0mt2udXxgxFIvC+b+Xy
         bIhT1W2PzfLrQOC8IqDMgN7a0Gwb6WR2O4/3dJPzXr8b/syjKxjdbSbfJAcVVqTjK9Sm
         sILIrSxTel79N6XXIIaiR5dAH2D5EOL7MFDZy2ALP3QwWa+bVKXbfPxuZpAYDx1CydJM
         KnoiKxB8VUMVV3HjLKfhN3X/mNytWxPwzlFa2mSbz+rQc/x3YMidVV2aSnbKR2962WFU
         UBZ3vF8mkjgCxju9LnfF09UHeAqMv/wuePrDUWS5DQfsLUOxSzDxG94CratDU4460yDw
         zrXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b="cFUGRWY/";
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
Received: from ozlabs.org (ozlabs.org. [203.11.71.1])
        by gmr-mx.google.com with ESMTPS id r23si635922pfr.6.2021.03.22.04.08.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Mar 2021 04:08:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted sender) client-ip=203.11.71.1;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4F3sDT0lfsz9sS8;
	Mon, 22 Mar 2021 22:08:08 +1100 (AEDT)
From: Michael Ellerman <mpe@ellerman.id.au>
To: Daniel Axtens <dja@axtens.net>, Balbir Singh <bsingharora@gmail.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com,
 christophe.leroy@csgroup.eu, aneesh.kumar@linux.ibm.com
Subject: Re: [PATCH v11 1/6] kasan: allow an architecture to disable inline
 instrumentation
In-Reply-To: <87r1k8av4j.fsf@dja-thinkpad.axtens.net>
References: <20210319144058.772525-1-dja@axtens.net>
 <20210319144058.772525-2-dja@axtens.net>
 <20210320014606.GB77072@balbir-desktop>
 <87r1k8av4j.fsf@dja-thinkpad.axtens.net>
Date: Mon, 22 Mar 2021 22:08:05 +1100
Message-ID: <87v99jh2ei.fsf@mpe.ellerman.id.au>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mpe@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ellerman.id.au header.s=201909 header.b="cFUGRWY/";       spf=pass
 (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted
 sender) smtp.mailfrom=mpe@ellerman.id.au
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

Daniel Axtens <dja@axtens.net> writes:
> Balbir Singh <bsingharora@gmail.com> writes:
>
>> On Sat, Mar 20, 2021 at 01:40:53AM +1100, Daniel Axtens wrote:
>>> For annoying architectural reasons, it's very difficult to support inline
>>> instrumentation on powerpc64.
>>
>> I think we can expand here and talk about how in hash mode, the vmalloc
>> address space is in a region of memory different than where kernel virtual
>> addresses are mapped. Did I recollect the reason correctly?
>
> I think that's _a_ reason, but for radix mode (which is all I support at
> the moment), the reason is a bit simpler.

Actually Aneesh fixed that in:

  0034d395f89d ("powerpc/mm/hash64: Map all the kernel regions in the same 0xc range")

The problem we had prior to that was that the linear mapping was at
(0xc << 60), vmalloc was at (0xd << 60), and vmemap was at (0xf << 60).

Meaning our shadow region would need to be more than (3 << 60) in size.

cheers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87v99jh2ei.fsf%40mpe.ellerman.id.au.
