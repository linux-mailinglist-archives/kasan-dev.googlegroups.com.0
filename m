Return-Path: <kasan-dev+bncBCY5VBNX2EDRB5NMVWDAMGQEEA2S3LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 94FE13AB553
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 16:04:38 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id jw3-20020a17090b4643b029016606f04954sf4079952pjb.9
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 07:04:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623938677; cv=pass;
        d=google.com; s=arc-20160816;
        b=R6o1wlBXCegNRMGqBWdA3Hr/7p1IcyBEsbElugeTxgs0wgInchjHo9T2PBDn5t5qzS
         nIUkiu6d9XGI6wsFQ/SIYAjO9LO/O1rWihs3UjkS8q80L3W2FWiZqBoASE+VoawsGtCl
         qep5bBtyKCKuXLKjYLRM0WhpIGAX3G2NoJMAPR+M0d6654+ypu0ViY3TwzXpoO2NklMQ
         YRq0wMiKPdLuGpkLwZk61IJtBcF0n3Uk/c6J+Fp/7fVNkUxwArtIx+gXhmKONiy28A6E
         JHYYYD6kwqBNvdugzwa8P+9ZyWtqm9WYSy1ZMe0f36iQ41o6zXPdHo3vv+lTrM7B6Gos
         dv8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=8Diac/7U8uF7dQ9IMkY2aDmKKx/mJ+C0efnZj1oTtuE=;
        b=abRISK7Exuvi8NQXRs8oHVlfpvgjfwrvKc6IFLfJ7M9fxbXqb3YUEXG/8jJQFM516Q
         CeuNdovSDraeB/hHBqLIx0gyxcyAPUVJuog3s6D1ussOifYGomj5Ukxxxsd+FofcYEnO
         3HNDbXiYZ7GgDr8gF4dCQ0Gs/I0ptG1Q520a1VT8B3qw/bqlepMU5NyIOu/y4+Jxmq+K
         2QVqGaj+VmTR4vAYe+XxDiKWXMQUzYDSN09ap8WQyWYhi6gRNWCABzcyU/uL2lTZd35F
         4rOM8Zmtvdb09Bfpnk1NNDcILarSkYA7MfTiDItN8o4spj4nxCS41LDbZG4GAXyeSJK5
         1FOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=lUWkoeD4;
       spf=pass (google.com: domain of bsingharora@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8Diac/7U8uF7dQ9IMkY2aDmKKx/mJ+C0efnZj1oTtuE=;
        b=dldovTGozS4ZCad+GYfadwu3aGd3OhODmCadbS+UAkBEeUEsLhX9AT3OSCqCnVoUJL
         +jqfGrGQVeuFQqxx23wIpcPgCkUD4gJlO3YzUS92WiYTSWBINv2u7ksG7eG5VhVo+uwk
         Bc4GU58fQEshnWi+KF4sCRhIXe9whsVUG+n2HT66NIyuoEFcrFHps0IFe9UryEIl+Q/p
         LPaxWwm32KtKROY1pPVBrgy+0Vy20k8MR7l5v5x0l3lJ6O/c+HCCVfh6fGO1hcW4615T
         6F2BceAcm4LJfygY+pKSQuQIsQirXpU9lEkAJlT8JcaOM8vqVmSpyfCKyENsLD1nnaRl
         v66w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8Diac/7U8uF7dQ9IMkY2aDmKKx/mJ+C0efnZj1oTtuE=;
        b=hNhs3CCInIpxN6sU3GuG9JnbaQ0W/16TBicVP7E7RURQm9odt1HfBUXaS24vnuWT5m
         JBmKM1EDCV2jdsn8+S6lVrzAIfjgHKLyX/mfVh0qIhy6pAr/4ZDREkzIFdg2WK7IWbKG
         55okPsaidKBc4NrAV9EZbyiBvWbkOIUKdr2Dr57/xb8hSL47F8YTKW0WNEQGtJRBsKHR
         9S/w3Q9cyTTJD6WZicoy8FkpWuu7nseW/3jQEGEJvTMY9Ig68Fwb2elhXfck/D9XmmRg
         to9uAC02vx0U9Hxfvx4+bE4GZrsnWieJpOvEyLf02w0a57iLw9pI+v+9Vjz3nOKQsO6W
         6Jpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8Diac/7U8uF7dQ9IMkY2aDmKKx/mJ+C0efnZj1oTtuE=;
        b=SQwxxtpXVO/9yGaGHnQGBIUlIshsHaWUiHifK7OqTUGfVmAVn1cduKZe5ujMxfwzl5
         3LKbyMnrLML4Slfexr1hiZ5LtSjdosmm4B2Ud7WnAxTNWdMTqVFjuJgxqE3+nK3Yblsx
         gKAxpjh1k4Sjbp1nVbLapJrcapx0e5IA4KDCl7wmN8ba9kg7g5s+faCloPrxQZnrh8Sb
         qha3LwlZ9lIHpoUGHsGQ8Bua7Kf0FgwpSkUeWf85UyxjOTxWcan2xa/ZvZ1141KfyjAI
         BrMha+/WZg5S/lMa25cFXdB0MDy6EViQ9T/VRqW1pXIEDCh+zJTo3RNCDfblBR6v9zOF
         itYA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533fJgfb6Wr9mgxNlr+h4i5khWVdBG4S/VxgDzPMnr6VF41hBYAi
	PuuVxJowvT2rxAZ43gI5BSU=
X-Google-Smtp-Source: ABdhPJzUCNeUKkpheCw6h5jinxAGCwGU/Nu3OTmBuebPJFKpY9Lq0VOo/DxBV7DjYPRFGd+GPwIIOg==
X-Received: by 2002:a17:903:2281:b029:113:1edb:97d0 with SMTP id b1-20020a1709032281b02901131edb97d0mr256508plh.64.1623938677363;
        Thu, 17 Jun 2021 07:04:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4107:: with SMTP id w7ls2929690pgp.3.gmail; Thu, 17 Jun
 2021 07:04:36 -0700 (PDT)
X-Received: by 2002:a63:2125:: with SMTP id h37mr5077601pgh.205.1623938676879;
        Thu, 17 Jun 2021 07:04:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623938676; cv=none;
        d=google.com; s=arc-20160816;
        b=BhjTFtcJ13L5IuL5eOASTPI9WHlyuVEojQ668QxK8ewb2A8eGBgw2L2a8XX0IMUoDD
         WvXaW6l7k+5FbbHOAsZsKDBgdnpkCUc+y8g8GGxoXWY2Z2KleTbgadWlqFtalpJXES8y
         EAejWuVXGq8654n3c6S83Q+FcaEH/sKai97UIRSXJ7I0hyBSBCzBbB/hHBuYDpnDR4Xi
         MRZLaq1ylePEl4moGxrBaofLva1DqdEWskYyLlnufBPwvNJqW5yQy1aIANNIwbTgrPDv
         LdZn3WPhTjk6W50KrpUyJI0hfiXWkpZBfRLRuWBJFlHEy0RdNCJLn5kZt7FOGthKIoye
         0hGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=m08QhGbjsqNMKDfakqlQtcqTK06PXTezleRaulhxGzY=;
        b=P0svPdM+6+6qJrNr7yP23cvuS3AvMBm2jTbUeLvdj0WITJS11D2qldHc5vYaaSGwaT
         buiihf10if10K9J/vpPOfHO37sSzELeOxgGv6oTKQ4sGXAdEpk/WcRizdAEUvEyaKYvB
         KIeTuTIjXLLkYID9b3khPH3OvUp2IkmGYWRsBg9zT+h2J8WVFEiL9nHyS0sq3cl5ZofW
         MQC0lCiU88ibLDZqz87Ry3lBKI4KH66LauaBlsgOjQRnh0qrA0qz0Tni2GuS+DtKtpHS
         GE37CGIRCppVhjvgML/15S4shEVFg4jNm9hrqwKXyKDRcdDnMVRut9JxAAyeNTMc98II
         6hgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=lUWkoeD4;
       spf=pass (google.com: domain of bsingharora@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x635.google.com (mail-pl1-x635.google.com. [2607:f8b0:4864:20::635])
        by gmr-mx.google.com with ESMTPS id d123si501820pfa.2.2021.06.17.07.04.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jun 2021 07:04:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of bsingharora@gmail.com designates 2607:f8b0:4864:20::635 as permitted sender) client-ip=2607:f8b0:4864:20::635;
Received: by mail-pl1-x635.google.com with SMTP id e7so2990593plj.7
        for <kasan-dev@googlegroups.com>; Thu, 17 Jun 2021 07:04:36 -0700 (PDT)
X-Received: by 2002:a17:90b:4b49:: with SMTP id mi9mr16281017pjb.219.1623938676419;
        Thu, 17 Jun 2021 07:04:36 -0700 (PDT)
Received: from localhost ([61.69.135.108])
        by smtp.gmail.com with ESMTPSA id c5sm5652006pfn.144.2021.06.17.07.04.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jun 2021 07:04:34 -0700 (PDT)
Date: Fri, 18 Jun 2021 00:04:31 +1000
From: Balbir Singh <bsingharora@gmail.com>
To: Daniel Axtens <dja@axtens.net>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, elver@google.com,
	akpm@linux-foundation.org, andreyknvl@gmail.com,
	linuxppc-dev@lists.ozlabs.org, christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com
Subject: Re: [PATCH v15 0/4] KASAN core changes for ppc64 radix KASAN
Message-ID: <YMtWb2HJx44HdgQC@balbir-desktop>
References: <20210617093032.103097-1-dja@axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210617093032.103097-1-dja@axtens.net>
X-Original-Sender: bsingharora@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=lUWkoeD4;       spf=pass
 (google.com: domain of bsingharora@gmail.com designates 2607:f8b0:4864:20::635
 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Jun 17, 2021 at 07:30:28PM +1000, Daniel Axtens wrote:
> Building on the work of Christophe, Aneesh and Balbir, I've ported
> KASAN to 64-bit Book3S kernels running on the Radix MMU. I've been
> trying this for a while, but we keep having collisions between the
> kasan code in the mm tree and the code I want to put in to the ppc
> tree.
> 
> This series just contains the kasan core changes that we need. These
> can go in via the mm tree. I will then propose the powerpc changes for
> a later cycle. (The most recent RFC for the powerpc changes is in the
> v12 series at
> https://lore.kernel.org/linux-mm/20210615014705.2234866-1-dja@axtens.net/
> )
> 
> v15 applies to next-20210611. There should be no noticeable changes to
> other platforms.
> 
> Changes since v14: Included a bunch of Reviewed-by:s, thanks
> Christophe and Marco. Cleaned up the build time error #ifdefs, thanks
> Christophe.
> 
> Changes since v13: move the MAX_PTR_PER_* definitions out of kasan and
> into pgtable.h. Add a build time error to hopefully prevent any
> confusion about when the new hook is applicable. Thanks Marco and
> Christophe.
> 
> Changes since v12: respond to Marco's review comments - clean up the
> help for ARCH_DISABLE_KASAN_INLINE, and add an arch readiness check to
> the new granule poisioning function. Thanks Marco.
> 
> Daniel Axtens (4):
>   kasan: allow an architecture to disable inline instrumentation
>   kasan: allow architectures to provide an outline readiness check
>   mm: define default MAX_PTRS_PER_* in include/pgtable.h
>   kasan: use MAX_PTRS_PER_* for early shadow tables
> 

The series seems reasonable

Reviewed-by: Balbir Singh <bsingharora@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YMtWb2HJx44HdgQC%40balbir-desktop.
