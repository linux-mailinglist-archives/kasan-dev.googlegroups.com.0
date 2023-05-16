Return-Path: <kasan-dev+bncBD52JJ7JXILRBUEWRORQMGQEODLCGJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1EDC770422B
	for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 02:16:18 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id a1e0cc1a2514c-783dba22afasf102601241.2
        for <lists+kasan-dev@lfdr.de>; Mon, 15 May 2023 17:16:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684196177; cv=pass;
        d=google.com; s=arc-20160816;
        b=ImeIPC68NPvEy5A/75GsxCJ88btlHXUrHKsoFTcBfikrPHOrjRaLe/G3Cp9szD/hIY
         /hlcqbzFpsay1Cd2k/SF0tvofyNvFvOLLoS2iUI5T4RL8wK8mPM4Q5AlrIiA2+XknAHM
         yECwEt7cvHt2357onvmziUK45I6XQN6S4vUSTMSH2oCHHz9nEICLZ9uzYx2fomD3azOt
         GfG8o9i34UXZ0bEL/lU3Emi3VRBs8BDG2m7ZPHfzANcpqk3jHt1Ndt+7J2k5VrLzXR79
         g0EJ0dmpK4aFLl9qNNE1DzptmBzSelgPKCqWI6F8KGLfXQo90ePrIDuumg1bOrC1ixZZ
         pCxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=l1KVgOJKMtnFZhV+CQJ1QURmlcoFAqzY7c0Bwt7ae18=;
        b=vwnjsJhoNlYl/YQ+IIh+/Iy55PHP+F34QT/NU3IM4Tzo0aN1edzLA7GmhDzo3MNwAs
         x+VrQJ/sE1kEFBcF//mtI0F4V1311P3WuFi+veFjbNghJXFO3XuzkYiMTYpTJhe5aZ3d
         0Yg0PKCZq03IpEzfhjPXeapmWfevLNXs0wz5p/zq85Nw4019HmpU562zfM7cZ75lDZJW
         CC4S7llYGsEB8qu0tQoih7r+LrlGk9MV68R3wkf81VJkvaooRYknnP9vtNiuRGVxRp6i
         rM3rthyy1dCKN7TzOj7Gzpo1y3uktCcRtZAnBfXjsf5w1R6PwnUNcQ9kHSDIP+w0lFLR
         Q6Sg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=4DT4IrQP;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684196177; x=1686788177;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=l1KVgOJKMtnFZhV+CQJ1QURmlcoFAqzY7c0Bwt7ae18=;
        b=nDlRYgdR3ultmob5q0pKh4wtmZ76SnuulZQ458rLuTgJPZbJ77UDHPGt1QJolf76Ek
         t3Z2+zWhfCM+Yms/3yzpGYJFUUTwps4uhBqomcxKkgDP6vIStI7n/Qpoa8F8WcE3wmym
         7FMragZsGJ1yCxmp2zpofl9Gzf7mn6fWbuBytmv92whambvm6zRgtJkJSNm9ckxjEb5W
         PRSjX4+FbNzBIEIT0LcF4JnNs/ggFwxmMuEdCVViHvyndP4GG6op52hze5WH4DTJAcdM
         3H1V5fhkCO+qp+uwqo9/EUjqf55H1h6dOswihseJMulUCJ1/5+chu5JjMabdIKCRxWDp
         RVOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684196177; x=1686788177;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=l1KVgOJKMtnFZhV+CQJ1QURmlcoFAqzY7c0Bwt7ae18=;
        b=D/+pvUss3DkLtUGp4CSCplR7RJKbOaR4k5KUlb6USmaMyIetcvUsFcPTL667cYcnFo
         864I8Jp1WBEUfPxvZUbXJuj25oP4nIgwkPjhaWewLAaKUiR2OoQ9c9jW4QlkvHA4M2kc
         iyL2np0lXUJdeHXZLxkzEn9hJh5W6+RRZBiWEKtH5xuPVhLIKgufMyFJzvh0nWL+YFix
         zzbiTSkJSDGZBFj6Yi+rJd035d3khVZ8W2OW6PCN95ZijrhwM3Hy6egUtogy6W7MfZsu
         14MgZsGxyrVG0G9ohcPB/kIhaj08+MytZ8OcOHyODMyl7yQYdtGf4qyXVbNdvX/AvLrs
         CWHw==
X-Gm-Message-State: AC+VfDxzKPM/sj1uraB1cUZOA1NeUi9t42cTSM6linIiG6I/2KmJ3Bmh
	voHGRRqreiUJSAcyS4/w3jQ=
X-Google-Smtp-Source: ACHHUZ6at/o0+WcBX4weBDxAgwAIhuE8OCpE01W55acKBExqwi21mzlaJ8aXeCkcAkMiGnw09gwBmg==
X-Received: by 2002:a9f:3053:0:b0:783:6afc:4ebf with SMTP id i19-20020a9f3053000000b007836afc4ebfmr7972053uab.0.1684196176828;
        Mon, 15 May 2023 17:16:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:2922:b0:42e:5faa:fb58 with SMTP id
 cz34-20020a056102292200b0042e5faafb58ls5143295vsb.11.-pod-prod-gmail; Mon, 15
 May 2023 17:16:16 -0700 (PDT)
X-Received: by 2002:a67:f9c3:0:b0:434:7757:f025 with SMTP id c3-20020a67f9c3000000b004347757f025mr13434887vsq.0.1684196176104;
        Mon, 15 May 2023 17:16:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684196176; cv=none;
        d=google.com; s=arc-20160816;
        b=Lxdq2pWWLVmQP79MjonDVmaZKSqWFL0HPpbQ2pGh5j7LhrYlExtlSVdpTX4bZi2YUx
         OIps+7Kdj67Vh60ddmA6YkLXHDcfW2m99YmXmOEHqRES08rg8UaRxHqhFC2AvshJfZdj
         lNA+Ph83zCLyDVnrqtqCFLvsdvD42DY6upa98sIj0ufGjIbfxohYt/glhjAIE/i3d5v+
         2Kwk0mX6TJlQcJRp/54zSgxUrnWICq8fCi7KyjZdzy3DNsowbC9R3L6rbQJa0YCqmP1S
         3yDzDJRA4rCUn1Gp2IlkH7A6IZiaIyyLujeyZmVWK7pfyvmoefovQOwAdF0u9JGW5ZLO
         vOrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=T6gh2qYVut9aSylVwiYmVdq2jPzWcix3qnUjMW+9u1Y=;
        b=mzou+pF15w1+cw4qp3PLaVdl+VBS4+PF6NlUS1VSc+XclnaUh0K3Kh1UEMyojgReWb
         V4GM0/xC9QlDDby00yH8l0SLQcFimpcjoiDU0Swc7/TG9fd3G+Zg6wKQMZ3UpbGcAapE
         rLOnNfGDiZbaiK2qY16SN8Buw+t94ogpF05MbtXLh3RMwyLSPko9ulkwMguiMdvg92IL
         gk5Q7FgG0JHHUQGMQoEM5owjrvHd/KwovAZFrvJ7bLGIG05VsfCQLgRacJUUYS3ALfjY
         K9eGiEFF0HL74n6jjS6U7Y5IZnhiu6iPsUnZSKkfByPu5/px9xIcroQtglIvbbCmHLYA
         C5PQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=4DT4IrQP;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id t12-20020ab03c0c000000b00783db9d50d2si50322uaw.0.2023.05.15.17.16.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 May 2023 17:16:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id d9443c01a7336-1aae90f5ebcso759405ad.1
        for <kasan-dev@googlegroups.com>; Mon, 15 May 2023 17:16:16 -0700 (PDT)
X-Received: by 2002:a17:903:2281:b0:1aa:dfdf:9232 with SMTP id b1-20020a170903228100b001aadfdf9232mr30882plh.16.1684196174906;
        Mon, 15 May 2023 17:16:14 -0700 (PDT)
Received: from google.com ([2620:15c:2d3:205:c825:9c0b:b4be:8ee4])
        by smtp.gmail.com with ESMTPSA id z21-20020aa791d5000000b006260526cf0csm12286564pfa.116.2023.05.15.17.16.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 May 2023 17:16:14 -0700 (PDT)
Date: Mon, 15 May 2023 17:16:09 -0700
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Qun-wei Lin =?utf-8?B?KOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	"surenb@google.com" <surenb@google.com>,
	Chinwen Chang =?utf-8?B?KOW8temMpuaWhyk=?= <chinwen.chang@mediatek.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	Kuan-Ying Lee =?utf-8?B?KOadjuWGoOepjik=?= <Kuan-Ying.Lee@mediatek.com>,
	Casper Li =?utf-8?B?KOadjuS4reamrik=?= <casper.li@mediatek.com>,
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
	vincenzo.frascino@arm.com,
	Alexandru Elisei <alexandru.elisei@arm.com>, will@kernel.org,
	eugenis@google.com, Steven Price <steven.price@arm.com>,
	stable@vger.kernel.org
Subject: Re: [PATCH 1/3] mm: Move arch_do_swap_page() call to before
 swap_free()
Message-ID: <ZGLLSYuedMsViDQG@google.com>
References: <20230512235755.1589034-1-pcc@google.com>
 <20230512235755.1589034-2-pcc@google.com>
 <7471013e-4afb-e445-5985-2441155fc82c@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <7471013e-4afb-e445-5985-2441155fc82c@redhat.com>
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=4DT4IrQP;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::62f as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Sat, May 13, 2023 at 05:29:53AM +0200, David Hildenbrand wrote:
> On 13.05.23 01:57, Peter Collingbourne wrote:
> > Commit c145e0b47c77 ("mm: streamline COW logic in do_swap_page()") moved
> > the call to swap_free() before the call to set_pte_at(), which meant that
> > the MTE tags could end up being freed before set_pte_at() had a chance
> > to restore them. One other possibility was to hook arch_do_swap_page(),
> > but this had a number of problems:
> > 
> > - The call to the hook was also after swap_free().
> > 
> > - The call to the hook was after the call to set_pte_at(), so there was a
> >    racy window where uninitialized metadata may be exposed to userspace.
> >    This likely also affects SPARC ADI, which implements this hook to
> >    restore tags.
> > 
> > - As a result of commit 1eba86c096e3 ("mm: change page type prior to
> >    adding page table entry"), we were also passing the new PTE as the
> >    oldpte argument, preventing the hook from knowing the swap index.
> > 
> > Fix all of these problems by moving the arch_do_swap_page() call before
> > the call to free_page(), and ensuring that we do not set orig_pte until
> > after the call.
> > 
> > Signed-off-by: Peter Collingbourne <pcc@google.com>
> > Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
> > Link: https://linux-review.googlesource.com/id/I6470efa669e8bd2f841049b8c61020c510678965
> > Cc: <stable@vger.kernel.org> # 6.1
> > Fixes: ca827d55ebaa ("mm, swap: Add infrastructure for saving page metadata on swap")
> > Fixes: 1eba86c096e3 ("mm: change page type prior to adding page table entry")
> 
> I'm confused. You say c145e0b47c77 changed something (which was after above
> commits), indicate that it fixes two other commits, and indicate "6.1" as
> stable which does not apply to any of these commits.

Sorry, the situation is indeed a bit confusing.

- In order to make the arch_do_swap_page() hook suitable for fixing the
  bug introduced by c145e0b47c77, patch 1 addresses a number of issues,
  including fixing bugs introduced by ca827d55ebaa and 1eba86c096e3,
  but we haven't fixed the c145e0b47c77 bug yet, so there's no Fixes:
  tag for it yet.

- Patch 2, relying on the fixes in patch 1, makes MTE install an
  arch_do_swap_page() hook (indirectly, by making arch_swap_restore()
  also hook arch_do_swap_page()), thereby fixing the c145e0b47c77 bug.

- 6.1 is the first stable version in which all 3 commits in my Fixes: tags
  are present, so that is the version that I've indicated in my stable
  tag for this series. In theory patch 1 could be applied to older kernel
  versions, but it wouldn't fix any problems that we are facing with MTE
  (because it only fixes problems relating to the arch_do_swap_page()
  hook, which older kernel versions don't hook with MTE), and there are
  some merge conflicts if we go back further anyway. If the SPARC folks
  (the previous only user of this hook) want to fix these issues with ADI,
  they can propose their own backport.

> > @@ -3959,7 +3960,6 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
> >   	VM_BUG_ON(!folio_test_anon(folio) ||
> >   			(pte_write(pte) && !PageAnonExclusive(page)));
> >   	set_pte_at(vma->vm_mm, vmf->address, vmf->pte, pte);
> > -	arch_do_swap_page(vma->vm_mm, vma, vmf->address, pte, vmf->orig_pte);
> >   	folio_unlock(folio);
> >   	if (folio != swapcache && swapcache) {
> 
> 
> You are moving the folio_free_swap() call after the folio_ref_count(folio)
> == 1 check, which means that such (previously) swapped pages that are
> exclusive cannot be detected as exclusive.

Ack. I will fix this in v2.

Peter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZGLLSYuedMsViDQG%40google.com.
