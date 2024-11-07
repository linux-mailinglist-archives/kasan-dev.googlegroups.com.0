Return-Path: <kasan-dev+bncBCY6ZYHFGUIJR7FRXEDBUBG352AN2@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id E56D89C0044
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Nov 2024 09:45:13 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-460e1786265sf11114271cf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Nov 2024 00:45:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730969112; cv=pass;
        d=google.com; s=arc-20240605;
        b=HB2Za6GMyoPyEM5ccDoWhiZgmYkBEqoS8SUWIRAK3FKP5U2YqC4ckww5mIULGiJgTP
         qTExSkF0dlqyguxag1lu9OX/f46zechOrDiePPZC4agXFtmBfHic02v9cgtJY8yz5zQv
         34Q8wuJuap6kKDyxR3UnCyxVN3cJsSA0EguqPQEeJCjcW3F1infbBqPR5IeJxDkebJVw
         TEpIWL/O8py0zkflC++RCSzqjZmiNZ3vsUwXUcRK5B0H8BUSDXf7qnixIxuDlrdO2u30
         aiRo5hx8QaRThHIjDy2azl4KCy+9bMlfrPuKKhs8I2uUBGHkkQkQne4VmUsMIpiFFzvY
         eGDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:date:message-id
         :subject:references:in-reply-to:cc:to:from:sender:dkim-signature;
        bh=F5NhnOA969dDgWaWETGPw2BpqzNYiKbFTZ3/dFEK+aU=;
        fh=MSkcv0LFhB2NpphnhIkp98HJAWlzay9H37P1hd/DmhY=;
        b=NgsD4K4WNxC5m29wc05FG2HbMlRhlHk2TGzOEIBaFGM/mzpQF0FTT9sdtkgb6GQdCh
         b3p0HX9xfaHSzzg2KEtvQ4lUePn/WPEBVqd2M6J4kboIr8HeUu6oii43YQMn4LP/vXcY
         +7LV+j7pD8vkm51Y6JZQt2TMU0NXzqKhewDVlIIayKUwor7K7bOqPfmNutyqB47LWPGM
         ENFgfWY7xoglrRrnGoFa/44lGue4R9I88y6racD1gBYS3Yj/kvXeu+YxboWXP5f+H7Ea
         ggySUVcaBv/zWDviiCTWdCLtFUFVYyCazHepmmGNJddJVPcJ30mJMqON+nqegratmMri
         0O5w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=ji9j7QV+;
       spf=pass (google.com: domain of michael@ellerman.id.au designates 150.107.74.76 as permitted sender) smtp.mailfrom=michael@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730969112; x=1731573912; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:date:message-id:subject:references
         :in-reply-to:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=F5NhnOA969dDgWaWETGPw2BpqzNYiKbFTZ3/dFEK+aU=;
        b=i3DmVrBOQ0lovWlNWG+bJMQuirmX1EyzgSQGJJ8USk4Cn6dfY8b9KylmWW84siwNPs
         yLrHgc0bfHaGCFIbQlv+764O6VCFp2bd99D42JrvdKX1xlGsIsoDTafk5rvWWYAEYvb/
         u7SFS3kIEz13SscYu7WerNJH1MIflesQp1ZF5OjYN/LVwtaedV9OKePZq0Qk6lHX96Je
         1TxRhddHKnh4JlrnIfnfTrXlU5nn5y/nNZrZpYLv2h4BC959sqGZQ28mzZM0oeWJQKzJ
         o2vSKYtbYt59PH2B5QZiS+vf/2tXKffcYOmTBdEXr8wvxFN8wV9SjWk2aTUQ3v0bK+Oi
         EfmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730969112; x=1731573912;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :date:message-id:subject:references:in-reply-to:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=F5NhnOA969dDgWaWETGPw2BpqzNYiKbFTZ3/dFEK+aU=;
        b=K2lo9v+WvYhgdIW58hpl+IRel0k/oCcy8laomCbbnyDL9r7rDj93vL9UI5eJ7+Px/I
         v3vatKuGOXB8ol71aMXh+9KCqYylajlPY+b61htxrX6cOkKoBkjnxsKa1uZ+mzlWjBxp
         SdnY1LVPx1SMJreJqAvD7JaQHAzWNapsFMsFIcAQu7dYVLwJiBNRfAZaj5guiL/aUwng
         QL8yBFVgfmNbzfrMjTUqnIRtgtjJWlQnZVuB+M4lsG2G/gwsV6RCFHIQuKb5UyXMBYXN
         QX27QwongAPkWdlw2IMnC2XC8SnG5XuRsnItDdeWE+1tZA4ECRLCWmHVcIDnyL61yGES
         Ojsw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVKUuRYf9KQrgLv0t6Dq0hAMcAU00RhQU24kx6dwIf4U/k5vEmJsFNE5++6URidSjt23z0phg==@lfdr.de
X-Gm-Message-State: AOJu0Yy12AGHJ9aEuIlAjaCAcoMq+P8t/OT8bfjMgZcHuWyBGuWWRPhA
	VvM8mgakrGa0fhs9av0nEdzHWOfIHpv3DLBcBqEJAUpaY2B4ge/0
X-Google-Smtp-Source: AGHT+IGD0kMRRZd5piWov6GWdHVp54uRKSh1xAwO+B/aG9jpEztmfDJNz3sneA5KGY8Av1H+CVylJg==
X-Received: by 2002:ac8:7d14:0:b0:460:aa51:8411 with SMTP id d75a77b69052e-4613bffb691mr668836981cf.24.1730969112402;
        Thu, 07 Nov 2024 00:45:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:4814:b0:458:4c68:593b with SMTP id
 d75a77b69052e-462fb32d9a6ls9276591cf.1.-pod-prod-07-us; Thu, 07 Nov 2024
 00:45:10 -0800 (PST)
X-Received: by 2002:a05:6102:510f:b0:4a4:9541:e384 with SMTP id ada2fe7eead31-4a8cfd693ecmr43481768137.23.1730969110362;
        Thu, 07 Nov 2024 00:45:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730969110; cv=none;
        d=google.com; s=arc-20240605;
        b=Tuu4Ap5OM7rfhhD7o7L0flmjWctL4ctA4GHmycgfC/bnUlvUdh2ynvyRd8d++N4n6a
         uj8YuE1lq4yUHYw0M85hLAWPaQ8v/8on0KD90Y3z4EkvygpxkFmEQXISlgTV/ovVrN+u
         nUmoN+exxNk6l39YMDrhmwQNXGK1JKW7FsJyfDGZKl1IBSDqMhhF0yeDFGX/bVx3RPWF
         ORhb7KNz9QrEmXmLHhww/EXtDUGb6xutSfgAHS8+TW7GKakPBFNYc+PCmMmmuc7DgTJS
         yXlDAvY2FleIu8KPMYLztX0/8eqCdKfKd/AM0rRzNeG5czsicKIrBmV3pl072LrjcRAG
         3i/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:date:message-id:subject
         :references:in-reply-to:cc:to:from:dkim-signature;
        bh=S8Ka+i9mImv1flw2WDBI2y32Prf/adbg6BktMA4093U=;
        fh=lGvrjRSOSX5KD8pruH/rooLyQZjsR3y0JzsGzboD+RA=;
        b=c5knYc+Fus+5sGC2Ob6GeoT4QAZ6P7ow5ow0Fan2mIyTWGy7ccMkI16shHCwvPeMWI
         FmffuInDnngopOp3tDrQDerr/M5/1Nv69AfjIyqbEoO7ImZRSfGNn2ryXTSQLS3siCJY
         usQ0PZgFFW9mHTg5OXDEDpO0izS0hHbganB6mrzt4LF6RlHtZuqZ9UU2jyxBrLCPGNiM
         CQfuIv8dYtE61+JcXiL9iXVkMAhqIocl2BvhurS1SFFPANUvfaZmLdBFMflfLaweuh4B
         UBbdUQ648kVUS6JNMOki+18zu+Zazcwmvc8RFowytdRt+m8QtdnqIdMYZ/2Sa/d32LFH
         ewhQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=ji9j7QV+;
       spf=pass (google.com: domain of michael@ellerman.id.au designates 150.107.74.76 as permitted sender) smtp.mailfrom=michael@ellerman.id.au
Received: from mail.ozlabs.org (gandalf.ozlabs.org. [150.107.74.76])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-856552e7d71si35960241.0.2024.11.07.00.45.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Nov 2024 00:45:09 -0800 (PST)
Received-SPF: pass (google.com: domain of michael@ellerman.id.au designates 150.107.74.76 as permitted sender) client-ip=150.107.74.76;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(Client did not present a certificate)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4XkbHL4PvJz4xG4;
	Thu,  7 Nov 2024 19:45:02 +1100 (AEDT)
From: Michael Ellerman <patch-notifications@ellerman.id.au>
To: linuxppc-dev@lists.ozlabs.org, "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, Heiko Carstens <hca@linux.ibm.com>, Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, Madhavan Srinivasan <maddy@linux.ibm.com>, Christophe Leroy <christophe.leroy@csgroup.eu>, Hari Bathini <hbathini@linux.ibm.com>, "Aneesh Kumar K . V" <aneesh.kumar@kernel.org>, Donet Tom <donettom@linux.ibm.com>, Pavithra Prakash <pavrampu@linux.ibm.com>, LKML <linux-kernel@vger.kernel.org>
In-Reply-To: <cover.1729271995.git.ritesh.list@gmail.com>
References: <cover.1729271995.git.ritesh.list@gmail.com>
Subject: Re: [PATCH v3 00/12] powerpc/kfence: Improve kfence support (mainly Hash)
Message-Id: <173096894640.18315.14301465980059494153.b4-ty@ellerman.id.au>
Date: Thu, 07 Nov 2024 19:42:26 +1100
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: michael@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ellerman.id.au header.s=201909 header.b=ji9j7QV+;       spf=pass
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

On Fri, 18 Oct 2024 22:59:41 +0530, Ritesh Harjani (IBM) wrote:
> v2 -> v3:
> ============
> 1. Addressed review comments from Christophe in patch-1: To check for
>    is_kfence_address before doing search in exception tables.
>    (Thanks for the review!)
> 
> 2. Separate out patch-1, which will need a separate tree for inclusion and
>    review from kfence/kasan folks since it's a kfence kunit test.
> 
> [...]

Applied to powerpc/next.

[01/12] powerpc: mm/fault: Fix kfence page fault reporting
        https://git.kernel.org/powerpc/c/06dbbb4d5f7126b6307ab807cbf04ecfc459b933
[02/12] book3s64/hash: Remove kfence support temporarily
        https://git.kernel.org/powerpc/c/47780e7eae783674b557cc16cf6852c0ce9dbbe9
[03/12] book3s64/hash: Refactor kernel linear map related calls
        https://git.kernel.org/powerpc/c/8b1085523fd22bf29a097d53c669a7dcf017d5ea
[04/12] book3s64/hash: Add hash_debug_pagealloc_add_slot() function
        https://git.kernel.org/powerpc/c/cc5734481b3c24ddee1551f9732d743453bca010
[05/12] book3s64/hash: Add hash_debug_pagealloc_alloc_slots() function
        https://git.kernel.org/powerpc/c/ff8631cdc23ad42f662a8510c57aeb0555ac3d5f
[06/12] book3s64/hash: Refactor hash__kernel_map_pages() function
        https://git.kernel.org/powerpc/c/43919f4154bebbef0a0d3004f1b022643d21082c
[07/12] book3s64/hash: Make kernel_map_linear_page() generic
        https://git.kernel.org/powerpc/c/685d942d00d8b0edf8431869028e23eac6cc4bab
[08/12] book3s64/hash: Disable debug_pagealloc if it requires more memory
        https://git.kernel.org/powerpc/c/47dd2e63d42a7a1b0a9c374d3a236f58b97c19e6
[09/12] book3s64/hash: Add kfence functionality
        https://git.kernel.org/powerpc/c/8fec58f503b296af87ffca3898965e3054f2b616
[10/12] book3s64/radix: Refactoring common kfence related functions
        https://git.kernel.org/powerpc/c/b5fbf7e2c6a403344e83139a14322f0c42911f2d
[11/12] book3s64/hash: Disable kfence if not early init
        https://git.kernel.org/powerpc/c/76b7d6463fc504ac266472f5948b83902dfca4c6
[12/12] book3s64/hash: Early detect debug_pagealloc size requirement
        https://git.kernel.org/powerpc/c/8846d9683884fa9ef5bb160011a748701216e186

cheers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/173096894640.18315.14301465980059494153.b4-ty%40ellerman.id.au.
