Return-Path: <kasan-dev+bncBDDL3KWR4EBRBVFPZ2PQMGQER7TM6EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5895669D0FC
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Feb 2023 16:55:01 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id g33-20020a0565123ba100b004dc6259b7acsf227214lfv.6
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Feb 2023 07:55:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676908500; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mhp2hwZEZptgE4/eyYeTQOPdUSelp7vot8+hNH16SCl5NCbAr5FKuVoE+O0wMxyAQB
         4MVvGylUfUB2wUaBm0SrBTorWFgOPbJrBpsqjhtQwoo4fblUW4RCxTtCaoPTCcONOG9c
         FdyPbnR08kY16SCBBWDRAjPQNNtUzPDC0Ken3/+fLB6FlnDIvO+TIy+bz+ELncza32Ha
         oLId9sOQZbJFKESZd6f9unliShSu5E/M2Q5XTWcTdb1eMn1FXlImw57skdu4nzcO5aWK
         xGaupmb1hkYq4bPwAZlLYLrtK892VBhwyi7nSAuAbTsrg6e9mRvEZejeCNbprv97DRyZ
         sBpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=jzTfPl+VayRQc8r0SflhfT2exHxrMODPrAwELTvoR50=;
        b=XqIKNvikz6TuqgNxWDowH5BaePU+Q10ofCds5d3HxTdqzYNeW/g8WJdDvFBkRGM/Ja
         WHK+n8CPZ8+g2HFHd2FTOHl3xius+wJDxmybsZBDuToUvSFuONXkSj2u9NwBbkkUQKsl
         /7B2WfUpORmoC55ZiGmNS3p8ODbeN2t7LtOOzl8U9as7XkwmdrwwsaZprxW55nSnCal1
         Ylg9q7Iy2kY56xOlu1xgwa7pklpzw4PE6N1yJBc9qgj/Z9Ss40i3HZD9xJXBaP12OTc+
         actzeDfyZapQe6SOvR6Sf2xqBlhf2fQUbDPZoowG3V0eNASBus9xklyymRin/BdM9wat
         YGqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jzTfPl+VayRQc8r0SflhfT2exHxrMODPrAwELTvoR50=;
        b=jC1faW1YqNjNAU4kWr9VQvPrK6eSllADMs6A0JHN0lX9PtxwBTXnAPJK+27uS8gKbl
         94kkw0RPQ9ra5cobu2mMfizpZS9741TYkXOio1zUMDCkVl5ExKpvv3P9pU5PXjV7YTce
         VxkRIS/msmEc5ddLe3CsvDjsY1MwDMQdLdTCFFWOnGar14rSldkQnXhhO3Ww20TyXjWI
         jKII1suUJSvZ92o0pd6Q9VYl+24VDpWica5t7rf1O6upnSCqcYoecPHRhBXb1zWHrO3q
         urjy/iIMLj+vVpLHW1ccN/aD331S3rp2yxiMDhCrjtuzn9K2uZuajp6YQrH0pRsBBAMf
         Vsuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jzTfPl+VayRQc8r0SflhfT2exHxrMODPrAwELTvoR50=;
        b=PAxXIAWqLESecujOQBXDPnqEeU2Etmihj4JqhaGEneGikXWfP2CVm0iO751IeYkXUu
         S4u2Nt5nTnTlQ0tkF3sTnmLe4xZUdZ5K4FotnFdmBaUx3sh8WWdNvndXyLg5efAslN5J
         9HuAJMhpFD+WjMuYTiQNpIEXJjrkPcfI+xYJ0hom6mv/TcZMEeEXi6B9lzhqjczArJao
         KEoV7a8G9RdanOWbyte44PbPMFy7oXwH4UuMpiPEF7iOmCRQ4m5fms9G/XUBMY465jQ7
         xxLArdYbrO19gN6lR3uAdKpY2g2eH4510H2MSk+9EueLHjByPF9FXSZ43awIoAttXP05
         /Vag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWZH9kvoCH8HX9rkDIfWYl9LioayLIyJynEFn7nwdZTlaxUMfCk
	0VJd/6O8FKTKgn9NvphZflY=
X-Google-Smtp-Source: AK7set8HMthRT4IciQ6Q2BIdmcn9WsMo/caUgplE+nbSFYQIBxFJ7pvQg7/mey5CuxhhRLoRrj1vlA==
X-Received: by 2002:a2e:a99b:0:b0:293:5140:7548 with SMTP id x27-20020a2ea99b000000b0029351407548mr1192636ljq.3.1676908500283;
        Mon, 20 Feb 2023 07:55:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:238b:b0:4db:3331:2b29 with SMTP id
 c11-20020a056512238b00b004db33312b29ls936488lfv.0.-pod-prod-gmail; Mon, 20
 Feb 2023 07:54:58 -0800 (PST)
X-Received: by 2002:ac2:4943:0:b0:4d5:95c9:4eb9 with SMTP id o3-20020ac24943000000b004d595c94eb9mr582699lfi.44.1676908498200;
        Mon, 20 Feb 2023 07:54:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676908498; cv=none;
        d=google.com; s=arc-20160816;
        b=SH5c5MgH8nmug0OrAcmv29WQ7ghqy1IQwrzKqHT6MFvWXqDcM+DPh+6FbZGGiD403q
         mAcX1mphmVCRRSYpJ6maEOZew4DvCadbLPfzOj4+RBjoomEU7I3XE0pV3qPOX4jViR3C
         MC+07lkWtJ4bxXjbKnsqxkEsN70K/4a7zzjJTgHIQABrSg8/GSQV7Re/dKexnPnXmXzr
         3oPN+CoQMqsKx2W3Wllsh/clDHgJLAhGkdJ3NQwsuFYTu6d66FsXGvahboX/3gXILk6U
         mOaQEas0S1O2gRptdkVUHBGWQhkNPym2gxf/S2xgmK4hlgrZ22dP8wghBvmzqUsBX8rz
         xsSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=GjAgm+DMsCoHLiPIjCFU15lhQszQNQTPCew618zHol4=;
        b=V18j8JoPap+RuM14bbDAYwkxy6XwNfUnrOFo+wI9GCtIfyagvooxON05bH5NHZdBVj
         pTojTVB8/JRgeIUaULCV5zi5kTVoWmK7vn6XSotsX4eVG7JBYMO37AZA+Cvne1gOFr6F
         OPx7AKOTK+8rUrGnB193TB4rjXnQbqJxwG5QiRpWs18G726VAVptgqh6jibWkzfN3vUG
         8sjs8+1RCxTbGLLwNrXKb6CjQbPz1WF90QHnTK4EST4E8bB4H+zWNAueG3A1dRdylaHM
         Mu5z62nGTGWQhsD5S9XXHai+930R9EdMwGkghy0JzDYmVtQB6I9OxSffB1iTILeZvMxF
         PxMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id b18-20020a056512305200b004d5e038aba2si52155lfb.7.2023.02.20.07.54.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Feb 2023 07:54:58 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 6F3E1B80B49;
	Mon, 20 Feb 2023 15:54:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 83CD1C433D2;
	Mon, 20 Feb 2023 15:54:54 +0000 (UTC)
Date: Mon, 20 Feb 2023 15:54:51 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Peter Collingbourne <pcc@google.com>
Cc: andreyknvl@gmail.com, linux-mm@kvack.org, kasan-dev@googlegroups.com,
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org,
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com
Subject: Re: [PATCH v2] kasan: call clear_page with a match-all tag instead
 of changing page tag
Message-ID: <Y/OXy3pQQDUybAgH@arm.com>
References: <20230216195924.3287772-1-pcc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230216195924.3287772-1-pcc@google.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Feb 16, 2023 at 11:59:24AM -0800, Peter Collingbourne wrote:
> Instead of changing the page's tag solely in order to obtain a pointer
> with a match-all tag and then changing it back again, just convert the
> pointer that we get from kmap_atomic() into one with a match-all tag
> before passing it to clear_page().
> 
> On a certain microarchitecture, this has been observed to cause a
> measurable improvement in microbenchmark performance, presumably as a
> result of being able to avoid the atomic operations on the page tag.
> 
> Signed-off-by: Peter Collingbourne <pcc@google.com>
> Link: https://linux-review.googlesource.com/id/I0249822cc29097ca7a04ad48e8eb14871f80e711

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

Not sure how this will go upstream, maybe the mm tree? Otherwise happy
to take it through the arm64 tree.

Thanks.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y/OXy3pQQDUybAgH%40arm.com.
