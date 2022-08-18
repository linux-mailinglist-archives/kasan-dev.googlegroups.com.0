Return-Path: <kasan-dev+bncBDT7BHX6YALRBFFZ62LQMGQE47ANLQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 44DA9597B39
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Aug 2022 03:57:42 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id q14-20020a6557ce000000b0041da9c3c244sf105642pgr.22
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 18:57:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660787860; cv=pass;
        d=google.com; s=arc-20160816;
        b=shPeJuneJZk9LR2fDZ+yAnL4Q1/f8QXusC52W7hvWtxOjgWWBTMJUtdLF8lwig33N9
         Y3glmdEtef9foyS5lCqQribBf41ocEqHU7cMp1yTEOVNn8ga0L3pQquCL0YJxPjUi46c
         zWFDVqVkGjahvFUMcdZe+LvrcvEUobpYH6qWaPI9oqCnrbcxwFPUVh6jTcWadU+A6oVp
         iLuXISBHrnbFi8u5Z75otN1NxrWy/KS5sCIQi6kYqxBDiiSHoJ8UAauJIItCmkqtc/IF
         eS6iXasbHh4ZZzxvPheai63btDkhar8UvAjvCkjBJYWpux0Kg6MjYHuXTeZeERtDSxuC
         0Xag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:references:cc:to:from
         :date:subject:message-id:mime-version:sender:dkim-signature;
        bh=YNjXvPTg5RbajI8q6UQfIjxr/aKyCz8gOCzkm1TJydg=;
        b=0pR7A2Hr4cX8yaupm1/fZiM/Su3ZHM3hzYu62fHhCpk6MVm9aOrtpPf3foev7+3Zvr
         TJW65BnO5UqJxsQHSm4lyNQsnVxO3TGGq8UdjU7uvkvrqcpBXPe8a19NsuKNpPuPOZT0
         0E/akL21MGn0VH3qT7m58PwTqR1PBonoQSn+LjIpwoNAcx/7yrfFbRTIKTyULVTXb1YD
         Z+9n/pjQXzPrYLUcoo1YVLa5Mf/p7gM95Qo2t9AAo1Ebk11AVbqKxa9IENwQFrjFqfVJ
         SandavzvyxgU8tlQmkAV39GuGTOnAp+hcFosr1VKYWWuXN5uZZCSP6ladzNsp79zHyE4
         tgwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of xuanzhuo@linux.alibaba.com designates 115.124.30.57 as permitted sender) smtp.mailfrom=xuanzhuo@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:cc:to:from:date:subject
         :message-id:mime-version:sender:from:to:cc;
        bh=YNjXvPTg5RbajI8q6UQfIjxr/aKyCz8gOCzkm1TJydg=;
        b=FXOPXDtFBgh+lYuR1ST7fnJY9rZObla6BDqDBerLhX5e3kpVRG77nxTNLkB0Qglrt/
         i7l5VZkRk2OIjJxItyPyRuoqguGyi/iGpHeannJPyLyWs7y0iK7UMMFuFzlrEkCiSvV8
         oIZBgc/zaCGwlZPLs0zJG9S+meAJRoX2ZIw4kK0M61VE/53hrVEaIwUk6v26PkP8+lab
         SFvM2aZJthzVJ+Ga3yb9/ilaOjdJPezbLmDg2T+rIiE9jyz96QQMxCoAP+WRtx4fUryF
         c/cffqi3+QLCZTKSK3+az/K3cV9FnsPhGfOTPAKlcaUhD/r87TYK5wOO2XcHedimDnoX
         e1lA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :references:cc:to:from:date:subject:message-id:mime-version
         :x-gm-message-state:sender:from:to:cc;
        bh=YNjXvPTg5RbajI8q6UQfIjxr/aKyCz8gOCzkm1TJydg=;
        b=Kp2NjQanhXMNbmm0BAbpvDu9J+IG5xhwOhNM1NyrtFzjl5mXZBQzyRaXkb58aOtKrx
         ELjCQe0NbmrX+n6dMZp+zX+tTKnefor2jo8gBi0q4QzYERHi4jHF8ThzNc5t3Pwa3o+y
         I/adtp97No7J/6dJrAP3bQIMOQzGOFzpE08rNtgVwbBMVrJEEfjLKw27AR2SoVr2Fq+S
         4GHUXGsnUcIQXSl8HXWa8NFMkCIxlzWukiiMrlRr6KiKLl8w0NcIetbNtu8JHtRmZd2h
         Rrc9j7u1kS0edzxFVSMoEfjmntycL1RfHDg4LgFyNM7eZgNhU/yVzYPEh5Tdm2zlRyPh
         4jhg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1k+diNc9z8h/KE4awm3ZQPq6sF9UxMWHPYKCPxMdM92ZOZOD1Q
	yc2JHpYSndl/oVUcXNwZyas=
X-Google-Smtp-Source: AA6agR7C1YEPsvYapMzyMvYiDNlqMfoOQickt43Sdca5i82e0da+Opc15PZmkGwo8uZd/HtcTRFRtQ==
X-Received: by 2002:a17:90b:2789:b0:1fa:c17c:92fa with SMTP id pw9-20020a17090b278900b001fac17c92famr769069pjb.197.1660787860514;
        Wed, 17 Aug 2022 18:57:40 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:1c8:b0:16e:ebfe:70e9 with SMTP id
 e8-20020a17090301c800b0016eebfe70e9ls287550plh.2.-pod-prod-gmail; Wed, 17 Aug
 2022 18:57:39 -0700 (PDT)
X-Received: by 2002:a17:90b:2684:b0:1f4:f2a7:f2b3 with SMTP id pl4-20020a17090b268400b001f4f2a7f2b3mr6620813pjb.70.1660787859646;
        Wed, 17 Aug 2022 18:57:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660787859; cv=none;
        d=google.com; s=arc-20160816;
        b=qpAeW3nOs83K2GyBeW2gWfUyv0vVJyLk2SOezBQEQdVvZWgUUKmeqtex2KZ+pALcLV
         dRcnkDL7bhO3Kdh7c3Hah/YqbLoXZtGVs4LdrsBqSKKRZC75DOlfjMTBZsHA40ktj4bf
         wLZKo50tx3wCVEho7iyvQ0Ar5yb9M7G2wpuiklYG4REvlki7UpeWiYwEpo1YyBXrfbUT
         tOZlI1o7N22tmZe0Ym4DDkOZhG7n/yy6A7zQ0GOJwXmDMxeB6tIB2eZMRvYzlaEQ+1eV
         lPu7MVlFlOOGVhVQbbHFcCu0t3jfyGd77jfckYQ4Rhf8HSbEeaj1sOwmzRILQfvkfTIl
         pPRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:references:cc:to:from:date:subject:message-id;
        bh=V13w2NCY80dUU6qIIgS6NnEd3OEqW7nSjnL5OU0UI1A=;
        b=mqwWDmEj/tDMvpV1s4PI2gPdI4Vo20XbixEpwvd161H2TlHP2qrxlozU4a+4rbYpUK
         kvSc6pvrBjZxV9GqEvyoSNF8UGJ2fC11LnssL07pQh1mOaTP1BuHMVxJFqTFAWRTAkZN
         gQD66gYoGtK5Sn13S3ckb4M8/4fEfxrYhT2fhSarG94d9b/R21fXdg4ob7R4AOZHxhc1
         c11B8ZTHxkhBKjTNNYbJ78p4jsnXz51DkMY1BxoUdA62+DgkEywL+qiF+1Wef5LidB8q
         UvxPMNlUyU7prsePkWm8V8zffB+KsbnG2dJ43xeqLThTlTFtTEpFTM6mgQUvHEs1SlF3
         zycQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of xuanzhuo@linux.alibaba.com designates 115.124.30.57 as permitted sender) smtp.mailfrom=xuanzhuo@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out30-57.freemail.mail.aliyun.com (out30-57.freemail.mail.aliyun.com. [115.124.30.57])
        by gmr-mx.google.com with ESMTPS id mj23-20020a17090b369700b001faca7cdb3fsi16487pjb.0.2022.08.17.18.57.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Aug 2022 18:57:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of xuanzhuo@linux.alibaba.com designates 115.124.30.57 as permitted sender) client-ip=115.124.30.57;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R141e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=ay29a033018046056;MF=xuanzhuo@linux.alibaba.com;NM=1;PH=DS;RN=19;SR=0;TI=SMTPD_---0VMYQwYj_1660787855;
Received: from localhost(mailfrom:xuanzhuo@linux.alibaba.com fp:SMTPD_---0VMYQwYj_1660787855)
          by smtp.aliyun-inc.com;
          Thu, 18 Aug 2022 09:57:36 +0800
Message-ID: <1660787737.7869372-1-xuanzhuo@linux.alibaba.com>
Subject: Re: upstream kernel crashes
Date: Thu, 18 Aug 2022 09:55:37 +0800
From: Xuan Zhuo <xuanzhuo@linux.alibaba.com>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Dmitry Vyukov <dvyukov@google.com>,
 James.Bottomley@hansenpartnership.com,
 andres@anarazel.de,
 axboe@kernel.dk,
 c@redhat.com,
 davem@davemloft.net,
 edumazet@google.com,
 gregkh@linuxfoundation.org,
 jasowang@redhat.com,
 kuba@kernel.org,
 linux-kernel@vger.kernel.org,
 linux@roeck-us.net,
 martin.petersen@oracle.com,
 netdev@vger.kernel.org,
 pabeni@redhat.com,
 virtualization@lists.linux-foundation.org,
 kasan-dev@googlegroups.com,
 mst@redhat.com
References: <20220815113729-mutt-send-email-mst@kernel.org>
 <20220815164503.jsoezxcm6q4u2b6j@awork3.anarazel.de>
 <20220815124748-mutt-send-email-mst@kernel.org>
 <20220815174617.z4chnftzcbv6frqr@awork3.anarazel.de>
 <20220815161423-mutt-send-email-mst@kernel.org>
 <20220815205330.m54g7vcs77r6owd6@awork3.anarazel.de>
 <20220815170444-mutt-send-email-mst@kernel.org>
 <20220817061359.200970-1-dvyukov@google.com>
 <1660718191.3631961-1-xuanzhuo@linux.alibaba.com>
 <CAHk-=wghjyi5cyDY96m4LtQ_i8Rdgt9Rsmd028XoU6RU=bsy_w@mail.gmail.com>
In-Reply-To: <CAHk-=wghjyi5cyDY96m4LtQ_i8Rdgt9Rsmd028XoU6RU=bsy_w@mail.gmail.com>
X-Original-Sender: xuanzhuo@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of xuanzhuo@linux.alibaba.com designates 115.124.30.57 as
 permitted sender) smtp.mailfrom=xuanzhuo@linux.alibaba.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Content-Type: text/plain; charset="UTF-8"
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

On Wed, 17 Aug 2022 08:58:20 -0700, Linus Torvalds <torvalds@linux-foundation.org> wrote:
> On Tue, Aug 16, 2022 at 11:47 PM Xuan Zhuo <xuanzhuo@linux.alibaba.com> wrote:
> >
> > +       BUG_ON(num != virtqueue_get_vring_size(vq));
> > +
>
> Please, no more BUG_ON.
>
> Add a WARN_ON_ONCE() and return an  error.

OK, I will post v2 with WARN_ON_ONCE().

Thanks.


>
>            Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1660787737.7869372-1-xuanzhuo%40linux.alibaba.com.
