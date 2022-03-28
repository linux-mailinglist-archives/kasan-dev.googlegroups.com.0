Return-Path: <kasan-dev+bncBDKPDS4R5ECRBE5TQ6JAMGQEF2JPGOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 8512A4E9B98
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 17:51:49 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id t12-20020a17090a448c00b001b9cbac9c43sf9292502pjg.2
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 08:51:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648482708; cv=pass;
        d=google.com; s=arc-20160816;
        b=HCwQ9+7clwzZfWrgyiaICYTxTJAbC6AHqi1tXhn/ygAcldM7aVK9xS/uAtsWaPWWXz
         Ux4470Qg4s03y9oNhVW6qv4zUxroxG+cJK1BYqhVQuGSkV7FHeVq5RTaAycQ0zNeDRtL
         yR31aL9+SIlO7o8Oo5l705X+ebFlLSbVtILqv7N0xIOvHn1DA0YeJAaPhGksf3JJpk2a
         6Chz011EGiFxyNMLwKn11+Ny5wWrMnqp39vVb8L9K7qvS+kdomZTrMGnMRGYyLHbyPID
         x+hqiEqNGtZ6niwJOCM1kqFo4ULiv4KcaYU01sPZxWJYinr+qcGhHyz+rn9uh2CHsH0l
         4tYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=1DF7X3V2nYinZSksA4w+u5LcE78Mi3pGAJOldUnqBYA=;
        b=ETR6Mwe0vRWAFq1uT96Qd2NYEecpk3G3xWyOd/hO7LJwFoxDwwk/1Fjkd5s9Imj85a
         5wZkm0IFouGn4o3p7XGCcUkqvfMBABZKMrVyCjvSjDkax5BWox8q0D15cEwSk6CunY2v
         qxtOYcbhTta5QwsJG0S8xhmmv9mLFPd9dPee3szODAob3N8ICb2YXln98eP8GVvK+1zM
         3LPorEqpoYw7ZECPfeMQrNUJvYAqHSQATtnQg8IGrLbqDmaB4QmKSYQOb9kppRvKxhlX
         6Vld1uku6VYmjynX2ySRY29rlHF22uNMuwgnD8uqD/EmSNTDPBFrGvCRKJiEip1hUsni
         C8fg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=VNxDfv9r;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1DF7X3V2nYinZSksA4w+u5LcE78Mi3pGAJOldUnqBYA=;
        b=Zlkhj1HQp62ZFLcViwVP6uBe8bcQ+HVKIfnT3P8mmqW09fIfSmSyc1RF0TTIa4Mgcx
         SMLgln2VuaMwtjbGU8rSa8HsEb8ahGzarnur8jRyGHZTOtn/a9h15kp/YiYxBhKmpmAg
         g1YinSKC3LDS+Y9UjzlvtBGaoydXonOSrE18zMymCig1wej+2obH+1hQX0/06LnGyStm
         BlW1YuhejoJyyqBIUSvnNL6J/cp3LLfH90E9L2TJhEai0lO+p4zQKtF7n8bQgGgyGXbE
         knhov6is93C3guocCKqaaG2pSv4irOz9zQtfaPF16GLKMMFLnin4NiMkqX6zeP3llcdc
         8EeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1DF7X3V2nYinZSksA4w+u5LcE78Mi3pGAJOldUnqBYA=;
        b=bfywsVcziVHAFp3qkqPKMnuupnc6J9KupGciy9xG96pneC3crGGr7/NjjbQgeJ0uf1
         GPHlDCJiVl9HLtZMUY4pmx/75tCQdMBBt8HrwR/bIG2DgEW4oSAL+dvm185VihyEayE9
         tY8naUXKecgeo19PbN4M0EmF3U1CNLMMPqiREcP+W78EY8T0LCqa4/2xtjRjT0f+ruvI
         9+LDjyZUoMOX1OSXoXdaYzz1l4IKAFpJC0lwHr/EEQLdNY10mk4JfMDjSj7OCrp8gYtp
         +ZVKFkdzpUIz7eMA710ZVZAgjHWwzu33g2eSsDaaP0xIevOnCSNE1mZ0kLMHg22I6+V6
         u0Pw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5311mscteVfa704e1BHWFy+lKvvUwllu84WnQkd8frNrmrAARylu
	qu89CLEK+SBxZ0BOv2FC2jk=
X-Google-Smtp-Source: ABdhPJwxQCL2PkJz7+EBAm2LE8bnnNNO5XIsTTQNMNvA4Z/IoGNlNih3fAymLGa8p7I4x3uFuymkpQ==
X-Received: by 2002:a05:6a00:2481:b0:4f6:b71f:3330 with SMTP id c1-20020a056a00248100b004f6b71f3330mr24022278pfv.47.1648482707980;
        Mon, 28 Mar 2022 08:51:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ced1:b0:154:624c:2ff4 with SMTP id
 d17-20020a170902ced100b00154624c2ff4ls10178666plg.8.gmail; Mon, 28 Mar 2022
 08:51:47 -0700 (PDT)
X-Received: by 2002:a17:90b:3908:b0:1c7:7a14:2083 with SMTP id ob8-20020a17090b390800b001c77a142083mr36675167pjb.230.1648482707414;
        Mon, 28 Mar 2022 08:51:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648482707; cv=none;
        d=google.com; s=arc-20160816;
        b=BZGw81Uu7aCFpygzCuzAgjZbCX7WraAqve19p75d6cOyvw04azFP8aaf8G+CcQDcRP
         /wuON1CiQinA7OWNhxt6ta3qOMTREYVt+aVhwmUkc6UndOuVXBqUg9UpIjR/piTcaxdS
         jtUrbqtzioiwCCOBYDnRmepLB6sS3eL1FA2CC61EkGh8iDNtWdgEkE6bEE15jdhUdNrp
         eZjtEwphfwZETb1+vwGSU0uengt1g3IcTYxIYohhw3KWVLfZTdI7e9yusNZPLoCLrcPP
         VN0Jg71wvn1YGRfLazKISqaQH5O+AznAqOUlgYIFdWqRncQeYFnbB99I5ojqo5nCCu0W
         DBXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Tin/HUePoSP0WPbVMV76tjgbiayi43biSRQ1KKujeeI=;
        b=w8UhtuqC9Nwfzw5bTVDC8BQNe033uD87iMgWtjMicvJvrjW2LvHJGty5ocjLjNjCcQ
         ZEdUPdLI6mMvZhnGGPt/vqFobO0O2UyrPLB0+HeGJePa65QCMSZ9/aBvPNFpPa09ZMz8
         QnxxmWynVRQQ6UHOVeIoMhfFSJHLRl5RFRy83WXYkYPQLz3KjFyKPweFklSmYRECk/kn
         01m23xRNp4xy2Jy0/5ygajE/3Hsu3mu0SHIoHU/5juzoN79aG7OxnuaC6gV2TdAwUppN
         HfJ8ahiNZx+33snfReGLcfFpRO2Bx/xZR0RDarB0sOtRhcqI1/t3b4Az07sh7C9otE2z
         udcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=VNxDfv9r;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
Received: from mail-yb1-xb36.google.com (mail-yb1-xb36.google.com. [2607:f8b0:4864:20::b36])
        by gmr-mx.google.com with ESMTPS id s3-20020a17090aad8300b001c75ad3207fsi627364pjq.3.2022.03.28.08.51.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Mar 2022 08:51:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::b36 as permitted sender) client-ip=2607:f8b0:4864:20::b36;
Received: by mail-yb1-xb36.google.com with SMTP id g9so24335958ybf.1
        for <kasan-dev@googlegroups.com>; Mon, 28 Mar 2022 08:51:47 -0700 (PDT)
X-Received: by 2002:a05:6902:120c:b0:639:86b2:76ba with SMTP id
 s12-20020a056902120c00b0063986b276bamr19563008ybu.254.1648482707142; Mon, 28
 Mar 2022 08:51:47 -0700 (PDT)
MIME-Version: 1.0
References: <20220328132843.16624-1-songmuchun@bytedance.com> <CANpmjNO=vMYhL_Uf3ewXvfWoan3q+cYjWV0jEze7toKSh2HRjg@mail.gmail.com>
In-Reply-To: <CANpmjNO=vMYhL_Uf3ewXvfWoan3q+cYjWV0jEze7toKSh2HRjg@mail.gmail.com>
From: Muchun Song <songmuchun@bytedance.com>
Date: Mon, 28 Mar 2022 23:51:11 +0800
Message-ID: <CAMZfGtWfudKnm71uNQtS-=+3_m25nsfPDo8-vZYzrktQbxHUMA@mail.gmail.com>
Subject: Re: [PATCH v2] mm: kfence: fix objcgs vector allocation
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Xiongchun duan <duanxiongchun@bytedance.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112
 header.b=VNxDfv9r;       spf=pass (google.com: domain of songmuchun@bytedance.com
 designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
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

On Mon, Mar 28, 2022 at 11:43 PM Marco Elver <elver@google.com> wrote:
>
> On Mon, 28 Mar 2022 at 15:28, Muchun Song <songmuchun@bytedance.com> wrote:
> >
> > If the kfence object is allocated to be used for objects vector, then
> > this slot of the pool eventually being occupied permanently since
> > the vector is never freed.  The solutions could be 1) freeing vector
> > when the kfence object is freed or 2) allocating all vectors statically.
> > Since the memory consumption of object vectors is low, it is better to
> > chose 2) to fix the issue and it is also can reduce overhead of vectors
> > allocating in the future.
> >
> > Fixes: d3fb45f370d9 ("mm, kfence: insert KFENCE hooks for SLAB")
> > Signed-off-by: Muchun Song <songmuchun@bytedance.com>
>
> Reviewed-by: Marco Elver <elver@google.com>

Thanks.

>
> Btw, how did you test this?
>

Yeah. No problem.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMZfGtWfudKnm71uNQtS-%3D%2B3_m25nsfPDo8-vZYzrktQbxHUMA%40mail.gmail.com.
