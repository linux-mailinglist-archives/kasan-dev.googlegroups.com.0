Return-Path: <kasan-dev+bncBDDL3KWR4EBRBPOSUKFAMGQEIGK3WBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E562411836
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Sep 2021 17:31:11 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id c4-20020a170902848400b0013a24e27075sf7162910plo.16
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Sep 2021 08:31:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632151870; cv=pass;
        d=google.com; s=arc-20160816;
        b=ohg5p0YYlExNC2V5z5xuqnvEmWHRP9H7ARnsSY9bavzoXNi8BegVHSVq2nu32We2/h
         /UVD6H2cy24+OTZMe8xRxEfQjlVFtxadEigpdg3tJGdzyt/g3UTdOgK/q1lASXzXL8+Q
         QAEcNhGT9vR6SQO8o40XOwA0Tpt6FRxCKVBTG1w7a35EL3IZ/1pP1a+1f4IxOdhGMrsd
         mMN04X/kJm2hAQdVQLlUZDxgO5af0bzdpcO7T0dh4LBiglL8bBE2nNXP8zaU7H9aqWg+
         CE0qun0kof2eqmeU2UJs1vJ/uNdJbtRtcNp/gh997fiszpNh9MUkVRl35abwxXr4MGOO
         3+eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=FFn8tbpKdGaQ7DL384J1nj6PydSHEQRxdM9hO5cgJkU=;
        b=qWL20RNUxlG+E//uXvLH9EPwwofFaLva2tG0x3JDnvPEMjJ1CedsOy/goFxTRAhf6e
         5e9ODEQcF/j3ZHlgvayz1S91Xix0dJTr8c4VbrvOI4H/kQVfzi0FzXX9o1x/kOnidGkR
         Lf+38PeR6zT3KSzbDE3PhzSiwJPoj+HfKJDI4+vzXBZrNPxXbFFkJ9b5OKl7jkEQZKJ0
         4BVHG1Ek/HL6yMl4z0sRY0PcpLS73WGTR5MyRzIMelZq22sV44A0Q8fi4D7sjbfgxT0g
         wKc+aXVenwudUHpiQo48RuETmX8OOl4lYT0AeVMP24MO4WoUzzQzUvUoPzKuxSmL782E
         UVeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FFn8tbpKdGaQ7DL384J1nj6PydSHEQRxdM9hO5cgJkU=;
        b=byRxRr18JUX7RF/vcdtjAUxxzHBZMvhmCGDvNOQ5U2q24cCMqmQuTe4UCPtiSlteLh
         j/p3NgrAiQQ+DkpI6wiHHI7XVJB3XjEZaptjEwrEhbsvoEez/40c1RyxqyXuOlTC/IdB
         lunj6p5hmxsGrnCbyEfYoGhEJTK9HMeNwJ73CSl8PFwD1gdPXMyF7YFPkwkwCuzWBzeu
         Pi83r+VcHsWLiovCOCsIn9Gh9FA2xlnME1TnZAoLNkHXyvHbVEn5jnmU2lJeMZI/XczP
         Fz3FNR+oSJtrFdwTIxirDKyuO5PFsJG6+qcmkmd1FwohoGr+Ts0h+0F77Htnc9S0jdw9
         9KNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FFn8tbpKdGaQ7DL384J1nj6PydSHEQRxdM9hO5cgJkU=;
        b=hAS9cTkxjLKLf7Eg61hUNOFMTrvHqHltzOdn1sYWCK2yAsmcmqgdz9kggkM2MJ49id
         xXzXCxCCm8J6ec9OMtj7LbqFRgO57QpAiEmBgf/Y63ZYF4V0GTPoPGZ5jGiA9fTh1paW
         XODvs+/WMcIbdy1c2CCcvLKpBGPZ2bP8YQQZ9haBeN7ncMg+hggOswuwaVlQhDhWlwGm
         CiNLcoz5E3M+h8skBLgDwCXO3vmbHQ1lPbqtPH5qdf3K2iwSo9cB/o7+60RjQF4j/EM2
         QMX3E10U3TDFPzLnSj20B1uRhWcASjEH/gv0DnVG4025A8LbaRtNQp21gSKzz9xIcGMI
         0I0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5318+kQCm1rj9Vp9Qriyq805EKTI3gTjbI0bf8A3GOppS/FEJpNl
	mpblTLlwI7hHoDTzvpzLlB8=
X-Google-Smtp-Source: ABdhPJwgS4V4SW2C4HG5UAsk7XngjMNKyjBb/WijDyDXhz0YmQ9KRBJQoG12c4QryAD2H/v59/f2BQ==
X-Received: by 2002:a17:90b:505:: with SMTP id r5mr23968340pjz.42.1632151869966;
        Mon, 20 Sep 2021 08:31:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:858a:: with SMTP id w10ls795957pfn.7.gmail; Mon, 20 Sep
 2021 08:31:09 -0700 (PDT)
X-Received: by 2002:a05:6a00:2284:b0:43d:fc72:e565 with SMTP id f4-20020a056a00228400b0043dfc72e565mr25772794pfe.84.1632151869286;
        Mon, 20 Sep 2021 08:31:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632151869; cv=none;
        d=google.com; s=arc-20160816;
        b=DmOij+OrrwbS98F89ZO5meGDpBUjP14stPisYxFogmogz1hYaT+dWZhKCBZwG3rXVB
         +810rNbGJ7f6eBxuUCqjKGKz5xJnwk7T2V3JllpZp6xoqcUQfvipJjOIuMvgvJPFVLjG
         x72zft9SOOzPUsS66Mvx8gkh8I5O+du3OFNdgMKLbmWdDe90GZeO96eVy/HrGeUOmEnc
         7h6Aueu8ildVF+lGhQzYkI32IFEmD7CTkg4DnpDjtwRPT5r4Rle4FIMtW21d/MmGHMDn
         JA2p/jiFPKOp2kObc8S6I93yAJp9CejHkmvi37E4nDko77ZYnICVOQTBKvcfXUpRS3BT
         A7iQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=ZmfN8yiE2E++TQHFksx9KXLAOqeKu8+R4jD9bkgUQig=;
        b=D9QeDMiD8NfaMzaCfTO6ci+xPMI0l6VZM3lxnRQqhcB5lAb54C4vrPHPXh74c7UGap
         IIj+FO/Zoqo+f6rBI5JdqPHuH+j8fEByyvsO4RlfvEMBFUK7ClufCGBfDHdUlcglFSnx
         0IJQUg/biAWCZGRtflrxtZwPX+ebfjf+X585OQ0WE5wKCWeKzclBngKGaexWxuce5c4n
         yNlf2E2/vNcSd7O8bcgniT0y130F5zcbScZvbHMGAVKLQEZz33OUCUJyChlXQUv3Fgwg
         vxKHSI2ZBHZQg9N70I3fGelI3wjX5xx6Dl2DrVr0SabYpNtLrrtqioZtxBdIzZ6mNbzU
         RWUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r7si12132pjp.0.2021.09.20.08.31.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 20 Sep 2021 08:31:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id CE8E760F38;
	Mon, 20 Sep 2021 15:31:06 +0000 (UTC)
Date: Mon, 20 Sep 2021 16:31:02 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH 1/5] kasan: Remove duplicate of kasan_flag_async
Message-ID: <YUipNseB8M6Eo0WR@arm.com>
References: <20210913081424.48613-1-vincenzo.frascino@arm.com>
 <20210913081424.48613-2-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210913081424.48613-2-vincenzo.frascino@arm.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
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

On Mon, Sep 13, 2021 at 09:14:20AM +0100, Vincenzo Frascino wrote:
> After merging async mode for KASAN_HW_TAGS a duplicate of the
> kasan_flag_async flag was left erroneously inside the code.
> 
> Remove the duplicate.
> 
> Note: This change does not bring functional changes to the code
> base.
> 
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Evgenii Stepanov <eugenis@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YUipNseB8M6Eo0WR%40arm.com.
