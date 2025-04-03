Return-Path: <kasan-dev+bncBCA3DTHS4QLRBMMLXS7QMGQEUIPVQFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4512EA7B1CF
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Apr 2025 00:03:31 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id 3f1490d57ef6-e6345bc7bd7sf3798729276.0
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Apr 2025 15:03:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743717810; cv=pass;
        d=google.com; s=arc-20240605;
        b=em4YDmZziasxPKi3mKzq8wOuLChAawd74p3KRk07ZQl1Xyd9i7prGlAqxhFmXQcmDO
         uDOAF6i8+nYPso2oFwTNFkTeqLLU4kLUCEmJZIQSWKQpCUFihVxt2N68KdNDtO1C3tEQ
         tsBsVDG9Hdq6Ngahv5rodqY9O1NgqPEbLcFokBB3iCLSt4YGSikRr+ey+OY1NyZC6z8u
         AV1liZ29nt1l6gvp1yAbjr7ym5lCFBJUFXIpB7YqD/3kJz1jUn/iyjGG5Bi2f+NtJtmN
         FLJLc42SaJ8PcXrftRBRtwYNSa6RUCKoXmuTO7DAgNAR9bNmfNnxMPahU1X4fKMN5cSA
         kgAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=66InGAiRgL8yLd5RlF6xTVP+zK/8WGFY9zTkh/y/wPk=;
        fh=cF7tKzHwmzKZI6dEf2RxqJrnMPREnWILt30TCui0XQw=;
        b=jfFUkfdk7oQtZNiFASS210ohCmTri3ZIF4BHYRdfdnmFr1K7bGzdkNi5l7ueZBUl+1
         twJrZBxVVLkWAnKeODnGJoTwO+DBVTMao7M1yYQffZjXELtAaVCCPRo50I6ab/ECh+Fq
         bIRJQffTlem1FINzs7WlKHqj9vwxODAL3k2Az2Y5j51I5d4zrVy4+jKwZa+oAq1C5CPd
         d0InVFd4XachYhSDxeQqJYFWT8h3rMxYTiodSqmc6HHV2EaRhdMWaKnWVjxXGcfjzXE0
         FhFHnuY+yt5fTp1mc5MkT9jUarKk97fqUahTqaeOvoU5oBzdctom+Z2MbwvOlpH49ISE
         wfmA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eLy56ujV;
       spf=pass (google.com: domain of jpoimboe@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743717810; x=1744322610; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=66InGAiRgL8yLd5RlF6xTVP+zK/8WGFY9zTkh/y/wPk=;
        b=F2xN8ELzK9Hct6EH0v6ZD3kThns8u6vsBpZJp8RGjAslEi/nmsqh5d1a3lz+liiTrk
         UceJFEqi5wr00zt+Sqof5/fFO5Pg8IvC7bq4H23z+TYMVCKWCcswkKGKX4wUBICJJJTZ
         lUARKwMNHtJIwWugDaPQblc02gO3EZsFOuvwhaynQ2Onre+t9ZVOReVGPShAKAzQ8IXN
         CCjptufIwr4gIR/xjxB6F2LZrrB+LTk/xSc8R4i0H+pHHteE4cmrf0hDL0n+ml4aKZks
         eNbGYmkw+62g2SubhKXz7qzkVJshAvIqSPYqQQAxMSon+unhPD1LC29YKcaqnXp0oyTY
         VYrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743717810; x=1744322610;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=66InGAiRgL8yLd5RlF6xTVP+zK/8WGFY9zTkh/y/wPk=;
        b=mgeBVaOBAEGWjKGIO2/nC+ySQQrkv2BCB4ezwbVXQJPU6yGi08OcrShm6wTRSfmR62
         DbTtF8WaHiYBBSVj+N3mBKDYCY+NgxmJenxdVi9tURQ/8K53hQV6EVj/v3reAgm74933
         XwXHysFpLvxUyvS87JWCt0No2TWDor5+NiSJ+/3OAV2ZwzdIuCORaMNiUht6C9FawrdZ
         DSSieNnLMyFpSOu5of/vTgIFaM6k9uFv3iScPNDZr/PMsnBB/+vxIYkbaubnLt5XE9z5
         PFFy0cbzgpHIDr9L2zkDjX2mFRUcfXyOs08eFLeSgnpGr84ppgMaDCfAO06z0O0Kk0cK
         ZAWQ==
X-Forwarded-Encrypted: i=2; AJvYcCWzkOfXiMl60kOr2o5RGhI+tchoBj6mlEs0IdLf8P3OnxmR1YZaDr+Ojk6TJaXVDu8JdMJWsA==@lfdr.de
X-Gm-Message-State: AOJu0Yy6KXexB1Tv75Zdsi8L780OO5IJHbnPINj6yHJ1HZZSrzVSCUA5
	YM5GquxMf3gS9guj8R91hSYoHboGrBs7NbgX/jWzjMsIVfCpoRTU
X-Google-Smtp-Source: AGHT+IFi5fmL6ask1LWuAro3cjjoYABCd8SR66bGdyhwqVtb2uVOwPkfFQ9v6as1+jbZfx4SbkIpGw==
X-Received: by 2002:a05:6902:1686:b0:e60:8b26:8c34 with SMTP id 3f1490d57ef6-e6e077c4709mr8852220276.22.1743717809826;
        Thu, 03 Apr 2025 15:03:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKXnecSD1uy7jAcbTSxBbtFwEzkEiozjsFm8t0X2+XMZw==
Received: by 2002:a25:aa49:0:b0:e63:401b:2dc2 with SMTP id 3f1490d57ef6-e6e19ef7673ls633186276.1.-pod-prod-00-us;
 Thu, 03 Apr 2025 15:03:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU/wSxSjJWpvGFa31d80d9vPDzsFBHEzgsu2vY+paOVjwyWwb3fdL0EkAjA4G45HcSDhfX7+v6T2CY=@googlegroups.com
X-Received: by 2002:a05:6902:1793:b0:e6d:ec89:be4d with SMTP id 3f1490d57ef6-e6e076ce00cmr9466388276.7.1743717808865;
        Thu, 03 Apr 2025 15:03:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743717808; cv=none;
        d=google.com; s=arc-20240605;
        b=NNsWrI5wh4bt4c01tte9axR80ZNlUZZdL1kCSReujMfaqWJmQGmYqaqN3ac9YPxuxD
         KdMiEkdl+NxiQV7TuRhFzphWp17xB+AA5/MSgTHRgogro4H9ma38nldpO5JK59HU+iul
         hmIac6g3Q4y8GHNeEOvnJRG1FnyrrMjJEhc5gWGgOFZ6zs1n1kUDcFxKFqcbf7jbno7i
         WHsu/tRa/RBtKz+Z8girrJDMk9COYtYpDwxODerBOjQa6tg4ZtLW8h3iKYQCxVdr05xF
         uVjk5N2hAads7k4VDA49Itzcrc62vbwl/f+cnza+Nx8Ni+WrnUt2XV45v7wpTsh0lGHy
         PB7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=99yoBIp0vcX2arVtUj7Gqtkyv7rwIf6J+LRUDwBTg+M=;
        fh=e19LbpJwhPB0Metq4X10zgMwE+8KqRxYqma78Ud+rWs=;
        b=CdV544A3POPtFdrALzyrh5JPMcw+0X9fQINrJBsYfVV72KPScjBI2oruycGFfbOFEb
         PqdWyMb5wNrEeuTZ/G+u286i0QjeTJghpm6uVeCJozuMOHlxyyU5FnFNhHIg28EZYTH1
         nx6SvgGlM2PFDM4syDoiL323LYq9jy548oA6dBvUtRLcdoosvwPolPguWd8rlwZfkAsu
         r6Nv3djPQf9mnN1Y3ZPILdlOS4pg1ZAweNNyGilWWnrsN/78tIBmUW24794LQpOjzU+J
         lxVyKqOEo7cpQUNOmKMMN3zQ+wuKMHz1+QEdXXp1fZFjL42ALKFyg4C161dzOZiX4oZR
         cT8g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eLy56ujV;
       spf=pass (google.com: domain of jpoimboe@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e6e0c95cde3si108234276.3.2025.04.03.15.03.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 03 Apr 2025 15:03:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of jpoimboe@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 7573AA468C0;
	Thu,  3 Apr 2025 21:57:59 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C43D0C4CEE3;
	Thu,  3 Apr 2025 22:03:25 +0000 (UTC)
Date: Thu, 3 Apr 2025 15:03:22 -0700
From: "'Josh Poimboeuf' via kasan-dev" <kasan-dev@googlegroups.com>
To: Randy Dunlap <rdunlap@infradead.org>
Cc: Stephen Rothwell <sfr@canb.auug.org.au>, 
	Linux Next Mailing List <linux-next@vger.kernel.org>, Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, kasan-dev@googlegroups.com
Subject: Re: linux-next: Tree for Apr 2 (objtool: KCOV)
Message-ID: <gz4mvn6q55buqjtk57jxke7tq4ge2nxoxj4rqd2xmjin5ulska@wtesjas4n3n3>
References: <20250402143503.28919c29@canb.auug.org.au>
 <ffe48f0a-9217-4f38-83dd-5fbc4de3eb73@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ffe48f0a-9217-4f38-83dd-5fbc4de3eb73@infradead.org>
X-Original-Sender: jpoimboe@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=eLy56ujV;       spf=pass
 (google.com: domain of jpoimboe@kernel.org designates 147.75.193.91 as
 permitted sender) smtp.mailfrom=jpoimboe@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Josh Poimboeuf <jpoimboe@kernel.org>
Reply-To: Josh Poimboeuf <jpoimboe@kernel.org>
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

On Wed, Apr 02, 2025 at 07:53:09PM -0700, Randy Dunlap wrote:
> 
> 
> On 4/1/25 8:35 PM, Stephen Rothwell wrote:
> > Hi all,
> > 
> > Changes since 20250401:
> > 
> 
> on x86_64, using 
> gcc (SUSE Linux) 14.2.1 20250220 [revision 9ffecde121af883b60bbe60d00425036bc873048]:
> 
> vmlinux.o: warning: objtool: __sanitizer_cov_trace_pc+0x37: RET before UNTRAIN

Thanks.  Turns out this is a duplicate of an issue for which I posted a
fix earlier:

  https://lore.kernel.org/41761c1db9acfc34d4f71d44284aa23b3f020f74.1743706046.git.jpoimboe@kernel.org

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/gz4mvn6q55buqjtk57jxke7tq4ge2nxoxj4rqd2xmjin5ulska%40wtesjas4n3n3.
