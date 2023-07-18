Return-Path: <kasan-dev+bncBDGZTDNQ3ICBBLEB3GSQMGQEZMLFBYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 23838757569
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jul 2023 09:35:10 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-403b0674ec8sf38047871cf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jul 2023 00:35:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689665709; cv=pass;
        d=google.com; s=arc-20160816;
        b=cJd2nnXnHvMVDhalEc0R8AvCcxRkOB8NeZvz8NtSbuK1kX7xT5+J+ihUyWB2be9Lv4
         yddH5cNQXyftoFFhQ4mYpDwUXGtQyHi7Qr7wnFaHJUzvG+r3vb5mH8WSTYx9g3qE5X6u
         jeHeUrnJ8Az9t25Y7xHmltC9gunaFy7QUxV1NhKYMl/SDIMVW9VQACjlPK8Voe9Q8uOw
         K/7G82ExYp805TTegArI2k0HWi/hmcjC6Nxv9xm7KtVgVyhZ/lDKd4sRMkXbh/hJ55Gg
         MVtubfXUz/QwGaZ6Dv9YzbBvKyu+K901XsglDEZs4Bnz/Pr/L/hS5HbByMTcJfuO/FEE
         AeBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=y0dY6WQQukDpRL/RckzRnDUGhDiS4eSimadY1aUeKiE=;
        fh=kGmpU18qIeuWxWR6Tm14lWzk4/s/cNVjNtDaRv1CHks=;
        b=D8sLjhHlvrwWhO5knvD47XUjRNqyDWRD5V6psuDzxGjW6rqWE0mbFmElh5nI6IE0Uu
         TCi+TDaOfVCHyOa1BjzC+XpfZtqeWnWN8w0WCvFTxkn911pMpxmO88yJzK2FElWjzaMd
         e/FLc4KqQ/svXXOcuIWNhiW1Ko7wDSwa2RpCU/9ee+WozJrdh4r4D4DPCMDayaYFkX/X
         GlSyfHGbyT16pwCIJZYPdHKivmDrDwV6T1A05dXN0vOo/hxfPR/u+B/UV/U+m3jitZUL
         dv821l+qDwbsx6sA/4IxrvbTGpdctDt/Q9KuG8/ZrnVbxCKG0eYM8HIUl1jfYP0gUj9q
         mlVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b="H/tYDf5V";
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689665709; x=1692257709;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=y0dY6WQQukDpRL/RckzRnDUGhDiS4eSimadY1aUeKiE=;
        b=GqbZYgWGNMNK8amO6V+zsJgJSlfa3NcH7bh6DCUpJxirrPPbUewScWPPt8b2ca1ycX
         hy5CXC4lgaVngi35RYwLvGmV2MRClKu8fT9eed+AeFaVHunCBBMbcnDJ1cLf1jItKdgG
         m0g6S0wDn0O2mHlh+Dy7WoLsB4EC/UX/XAV5ZvcEERj3xAwfm3VbkLYJYUPB3J/PkQd+
         BufeQ5hOsq8cSWYZkVf1oALYwdO6b8RbG/T0sFbLKY8/+TAzUeMCBNMRHEKjYcaZxqRK
         v3fYAeZzMvRoNfRwJEJMBTZiq4yFNwdbji7Iyywu/gP1ktE3PLTD1AA9IvWRkDo1fX7e
         zHgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689665709; x=1692257709;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=y0dY6WQQukDpRL/RckzRnDUGhDiS4eSimadY1aUeKiE=;
        b=jQmB5vJqfYmCe8Mc1NcLLdjsU2Kmsh5Y8Bq8FYHO9978x9BcL4AN12zXgI93iRtWc4
         H05nFGbiNnX71cnGUXmOLnr4a9Yt2NthRkfQ30AYnTn4lPZ5tXya0dkKle0nREAIHSKr
         jeBAS86S6Ycj5WezjkZ9dqMpohIWT7MgHxsnBd90IFLvrVUBSs6OQurJtLECNcYc89PE
         I4Y7oEDJuHC2n/pMfNM7Ql5Ku+n45yWU7vTJiBoyc98l9zSUM1M62/8T5CRuNs7kxMDl
         sJGoWfjjyWBZ6GSnN+s/ZKXTu63/S8/a0G+Zkq+b4s8FpIQyXBL1tElgPGVluWoQyAUu
         K9vQ==
X-Gm-Message-State: ABy/qLZnRXpu964sw3/XOY1gUl0gNFvrd5iHyO6vnrUQdTKuvbs6JBV5
	Rep3nnRz1+vvH1bDHLDvrMA=
X-Google-Smtp-Source: APBJJlH7kcbQgLp9QLko4YcDZCMxmziHtpDtZ+knJo6SqyTuQHhWhAvrL8p0FWFnPrN0lp8IaC4CHw==
X-Received: by 2002:a05:622a:1a8d:b0:403:fd62:ce75 with SMTP id s13-20020a05622a1a8d00b00403fd62ce75mr145042qtc.5.1689665708838;
        Tue, 18 Jul 2023 00:35:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4791:0:b0:403:ab5a:9c10 with SMTP id k17-20020ac84791000000b00403ab5a9c10ls56825qtq.0.-pod-prod-03-us;
 Tue, 18 Jul 2023 00:35:08 -0700 (PDT)
X-Received: by 2002:ac8:58ce:0:b0:403:a338:2bb9 with SMTP id u14-20020ac858ce000000b00403a3382bb9mr14671003qta.46.1689665708160;
        Tue, 18 Jul 2023 00:35:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689665708; cv=none;
        d=google.com; s=arc-20160816;
        b=ntEN9AV+lPomUC5dCB9gjqp5kDHgVU9x5yK3qLS03whGYLjzO400xVSyhRTgAxHXZ/
         Tbp+UEMRE2SEbT8WwwTwL0tw5t+QWF1cWUdzEfWQWdvBH2m9WNfLwuWO9EmJFvJeL2rM
         Z5OpUpKU1/W5ZnN7fFClGCg9Q9VG6ZYS8cizbKl9Fx0ZUn0/74PNEBzv/FBqLukj8Onn
         cxBrEKrXz3BJT9zodQwMGTE2XdNNo1Wd85StVTFoLbmm6ylqqAVoeHf58FSvBTpSjc2D
         4+3+XsvgLkdWFvQ6K/Gz8spiE5+Roqd5jEXP+ELDDbHq5oCO2FOZNkjqv4RrCHO8tQMU
         3aVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=jgI1g6KuDBssW0xC2nWGPlICaywUY7ceINZ1wtR5IPw=;
        fh=RRQysK4pMbWEknOkJw26PKZ2ruZSr5AxDIz17Rud4U0=;
        b=rz8csdRSrX7Jms4jcj3V4P0Y6VDkuY4CBL9f/26xR5VxaBydXOtdEXBVX/KwryJ1NL
         7Tnh6jhMSs8fVG+yYjz0o2/JYC4opOxlh9DkqVGjmcL5sR+a/iZkm60+FtYvz7GbBT0Z
         eNpCnSKG6211nhQto5RdHxqPcA6jkoJb0AGJaAzMW0YnUBXUgjFc19/HFkVHyubVVY4m
         Fv+OI2ixgIa+JIG4vwIvhZ3s0kkIaVYfCv3cyYOAs4QNOcfmrH/fPcUV9X0+MT9BeglN
         iQPMFoW1SR4UkLXY1ohy5709NzJ7TpSUXvTK+z+kfPGUYxsspvTgn7saEWxKUl4xdFeA
         gbng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b="H/tYDf5V";
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-ot1-x335.google.com (mail-ot1-x335.google.com. [2607:f8b0:4864:20::335])
        by gmr-mx.google.com with ESMTPS id fv24-20020a05622a4a1800b00403beff66b3si97042qtb.0.2023.07.18.00.35.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Jul 2023 00:35:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::335 as permitted sender) client-ip=2607:f8b0:4864:20::335;
Received: by mail-ot1-x335.google.com with SMTP id 46e09a7af769-6b9bf0252f3so2971200a34.2
        for <kasan-dev@googlegroups.com>; Tue, 18 Jul 2023 00:35:08 -0700 (PDT)
X-Received: by 2002:a05:6358:428e:b0:135:85ec:a092 with SMTP id s14-20020a056358428e00b0013585eca092mr12638757rwc.26.1689665707481;
        Tue, 18 Jul 2023 00:35:07 -0700 (PDT)
Received: from [10.254.181.133] ([139.177.225.252])
        by smtp.gmail.com with ESMTPSA id m22-20020a637116000000b0055c558ac4edsm1028564pgc.46.2023.07.18.00.35.04
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Jul 2023 00:35:07 -0700 (PDT)
Message-ID: <f0aa25be-8f44-b71c-baf9-f22890c32329@bytedance.com>
Date: Tue, 18 Jul 2023 15:35:01 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:102.0)
 Gecko/20100101 Thunderbird/102.13.0
Subject: Re: [PATCH v2] mm: kfence: allocate kfence_metadata at runtime
To: Marco Elver <elver@google.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, muchun.song@linux.dev,
 Peng Zhang <zhangpeng.00@bytedance.com>
References: <20230712081616.45177-1-zhangpeng.00@bytedance.com>
 <CANpmjNOhNQuBZAgOKLv4+4UoFK1b_8PP0EzWzkuyyGE0bg+weg@mail.gmail.com>
From: "'Peng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CANpmjNOhNQuBZAgOKLv4+4UoFK1b_8PP0EzWzkuyyGE0bg+weg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: zhangpeng.00@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b="H/tYDf5V";       spf=pass
 (google.com: domain of zhangpeng.00@bytedance.com designates
 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
X-Original-From: Peng Zhang <zhangpeng.00@bytedance.com>
Reply-To: Peng Zhang <zhangpeng.00@bytedance.com>
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

Thank you for your review, I have updated v3[1] with all
the changes you mentioned.

[1] 
https://lore.kernel.org/lkml/20230718073019.52513-1-zhangpeng.00@bytedance.com/

Thanks,
Peng

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f0aa25be-8f44-b71c-baf9-f22890c32329%40bytedance.com.
