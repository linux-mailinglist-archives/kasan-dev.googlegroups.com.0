Return-Path: <kasan-dev+bncBAABB7PQQWIQMGQEESAECPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id B0CD44CCBBC
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Mar 2022 03:25:02 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id mm6-20020a17090b358600b001bf2381b255sf686134pjb.6
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Mar 2022 18:25:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646360701; cv=pass;
        d=google.com; s=arc-20160816;
        b=Km2PSE0V/V9ExjBkblZQEqwq3JE3nMclxdUl42e32O02VQRP4jfRc+QxjqyclfLogy
         JCBXlU1wqDVLusQlS2R0mvXk/waWNKvNQ2QYsMvwEYGI5K5nZqVzfmgWQekJ/G8aESje
         fZhpvTefSmX71LIdu2HPaSMGs/96EDpMZYhjHIAM9+cK0f2NaRAvb+B/oupf2NUG/ldG
         2fcoCPAIATSurYyOaZ9/UUfkNIqYsmjEEf3it7fDpxM6aEQOjpOZMHVzxRHzNZLHSKf+
         Me9umXq1NU7YF61p937DbwYizfqrAuURH9wiXkCghPbkdmzFJdOjpE5JYTnaai3Vr+6d
         m8IA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=uynty0CtYySaTifVoUTsMt/ahAwkxtGx3X84fbUHV/c=;
        b=Nv8X75bnpyWFhyJz8y33d7HZErq86YdJzSYk4lkPZ6KS5d04ZelXmoRB4t63+nTtRj
         rZHPvqYjcWUbbHlxCpFnHQkRgWmKcjwwxfcEsRK+PxbM4Ft7erxwd/eov3pzgJFU2oz0
         EwcoKXa7D4uM2ofLZFHULij5sYK6UPYSigMx0S0wBnhF7EkobM6OksZdi4vp8UqfXhEd
         hJAx05UjaefLKTM9I0FjjWe83+AVsMuJSHgBwJWweVdQlZOutUtBGT11LOIxOLG/Ejcm
         HjnuS2LskW+JB9VdbqDh8W2mBGPdc5XwTevie3P6TrLNA/xwMfr7026do1f5le0puE7e
         7auA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.57 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uynty0CtYySaTifVoUTsMt/ahAwkxtGx3X84fbUHV/c=;
        b=Hw8eYeh6qgMwaHZt3q5u7KkgciZQrVDfOoakPatWdfjbbGHHMtbwT5ZYW/HxHaGsCu
         WOE8uluX9ph6E1ib5AIywGI6wmwSVwXC70t14lDfRwVVz2OFqiiNk8zvEe6rjTvL3RnW
         u9JBkHAT6HrMp11A/bfFobt1jLsSqmSiUyrxw8Zy/Y0Xz0ICDQhYl91qAku9gu8lyW45
         9Z6pnK9r5jnJ1mHzxWfMwdySXPWA82Bk0MTKKAHFJir80BSJirXQxIv0+gmT99eFq+xb
         NCAUxDPJ7xCR3WmEGbcqF1i77UmeFlu+Qcd4+qfEN30Y9jFCGB1ZUtA3kNUSzGhyOZFZ
         jCVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uynty0CtYySaTifVoUTsMt/ahAwkxtGx3X84fbUHV/c=;
        b=v9NYDw/LiAxt86PVgPR1SNCnBXq9e6r4SQTsNMJZuUQMrpc+YksvQaGg5d1n9Nmr9K
         OCfEKKGDusDNgPd3QsZO0ae6nhSuFXBLjD1mNhZ/9qGoApBOXe4QWheqkSKxoYQDnnvS
         C2W5FcujwqM9xN5pWIyhryxmAe/GWrjAU3qJQ5ZgZm/SlNt8EjpMxPCTc6tU9350xBUJ
         YslBIQVgmd7ait0VU/cp8vSPdMdlGjhBwCbPcKvzi8AlLKAh+Cv7S0w+kqoH/yq8sOAH
         tLexvEUq3zBBrSQXJQvWzNiEQ74tu3zZPKManQcvZiiweTg434cuwm7Vgc30kRowDwXe
         1YyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531cKdCkSymmiYjO/ZbmMrz0dr9nwrrf5PSmVINVvpQ8YMDkTPcf
	UsJz/bqT9qV7ha+ExVRX5IA=
X-Google-Smtp-Source: ABdhPJwm2dkxXAg3QXAv023Z7NGo0dkXivDIvy26BD0dIOjJt+GCfHdlhoIfIspnhQ0sYPZxA+TiYQ==
X-Received: by 2002:a17:902:8a91:b0:14f:969b:f6be with SMTP id p17-20020a1709028a9100b0014f969bf6bemr39424660plo.161.1646360701240;
        Thu, 03 Mar 2022 18:25:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d48f:b0:150:b5b:5387 with SMTP id
 c15-20020a170902d48f00b001500b5b5387ls3488971plg.4.gmail; Thu, 03 Mar 2022
 18:25:00 -0800 (PST)
X-Received: by 2002:a17:902:76c7:b0:14f:cbb1:71da with SMTP id j7-20020a17090276c700b0014fcbb171damr39060937plt.39.1646360700720;
        Thu, 03 Mar 2022 18:25:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646360700; cv=none;
        d=google.com; s=arc-20160816;
        b=ZqltpMQ9Ki9FxdLETOkPbmZ0AV2qfqdPG3YIhlGCERtny5D/kHWENKfb8TKzacddsb
         Uhx1mfv5mVbrCIsdVwoBaLRRLl87wfbCguwitDJDNc7j2KJHPWDUPYm1DTmehqJPY9g5
         5KfaU4MWcpzHJ+4/urBZhvlqgc2Iv6J/CEBij3R5eEHDWkJgFL81aY6I36aiPLE0EtBi
         UxsgORmDKED1A2NdBV1WGMvQCqEas+wkc/WUZobHYnox5jThZ7aba1k5QtnDAIULu4CI
         4Zn7IOAFG3t96UWIjt8LT125gmb9cYOcdMESZZUXvPPdL2LPoyDh25Ug4q+AQeVZHI4S
         wCOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=JfdzVvLooHJF9L8WODqVVEN3n1zOdAfiFCmeSEp2dM0=;
        b=00xrZD+DImenTWW1pSTDBbDNu2N1btssyyIcaBQqaQ8/xhaMorYycAwhYWMWCCxxJ1
         gVLQVqsq6cvcM1EPCwRWfr9d/8GI0I5+K8jhaMEsv9fvvIiThAzKFJ7ng2JWc46H4ilb
         rtfGIAauIRhw8qfIT7McVsExELBcuEDrK231AAAur6D4uIPGtwohzRzMrpHqGgyzpIV6
         UuLcqia2ci6GuEy6zlofvcKnq3sgmLb5aPP3oHeif+lqza/jKGFyWJN0TWAAWHB7puRq
         lMGJ77RltsrakLs0oWP0wGmmXiXm7p+Y2uG6a7P730UHnCA2Fu56nnrZ0yhcJ6jYWTDR
         ua7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.57 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out30-57.freemail.mail.aliyun.com (out30-57.freemail.mail.aliyun.com. [115.124.30.57])
        by gmr-mx.google.com with ESMTPS id t2-20020a170902d20200b0014f069fe9a0si150829ply.6.2022.03.03.18.24.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 03 Mar 2022 18:25:00 -0800 (PST)
Received-SPF: pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.57 as permitted sender) client-ip=115.124.30.57;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R901e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=e01e04400;MF=dtcccc@linux.alibaba.com;NM=1;PH=DS;RN=7;SR=0;TI=SMTPD_---0V6AHJDk_1646360695;
Received: from 30.97.48.223(mailfrom:dtcccc@linux.alibaba.com fp:SMTPD_---0V6AHJDk_1646360695)
          by smtp.aliyun-inc.com(127.0.0.1);
          Fri, 04 Mar 2022 10:24:56 +0800
Message-ID: <7c14bb40-1e7b-9819-1634-e9e9051726fa@linux.alibaba.com>
Date: Fri, 4 Mar 2022 10:24:55 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0)
 Gecko/20100101 Thunderbird/91.6.1
Subject: Re: [RFC PATCH 0/2] Alloc kfence_pool after system startup
Content-Language: en-US
To: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Linux Memory Management List <linux-mm@kvack.org>,
 LKML <linux-kernel@vger.kernel.org>
References: <20220303031505.28495-1-dtcccc@linux.alibaba.com>
 <CAG_fn=Wd5GMFojbvdZkysBQ5Auy5YYRdmZfjSVMq8gpDMRZ_3w@mail.gmail.com>
 <CANpmjNPBYgNMzQDKjNYFTkKnWwMe29gpXd2b9icFSnAwstW-jQ@mail.gmail.com>
From: Tianchen Ding <dtcccc@linux.alibaba.com>
In-Reply-To: <CANpmjNPBYgNMzQDKjNYFTkKnWwMe29gpXd2b9icFSnAwstW-jQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dtcccc@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.57 as
 permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
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

On 2022/3/3 17:30, Marco Elver wrote:

Thanks for your replies.
I do see setting a large sample_interval means almost disabling KFENCE.
In fact, my point is to provide a more =E2=80=9Cflexible=E2=80=9D way. Sinc=
e some Ops=20
may be glad to use something like on/off switch than 10000ms interval. :-)

> On Thu, 3 Mar 2022 at 10:05, Alexander Potapenko <glider@google.com> wrot=
e:
>=20
> I share Alex's concerns.
>=20
>> On Thu, Mar 3, 2022 at 4:15 AM Tianchen Ding <dtcccc@linux.alibaba.com> =
wrote:
>>>
>>> KFENCE aims at production environments, but it does not allow enabling
>>> after system startup because kfence_pool only alloc pages from memblock=
.
>>> Consider the following production scene:
>>> At first, for performance considerations, production machines do not
>>> enable KFENCE.
>>
>> What are the performance considerations you have in mind? Are you runnin=
g KFENCE with a very aggressive sampling rate?
>=20
> Indeed, what is wrong with simply starting up KFENCE with a sample
> interval of 10000? However, I very much doubt that you'll notice any
> performance issues above 500ms.
>=20
> Do let us know what performance issues you have seen. It may be
> related to an earlier version of KFENCE but has since been fixed (see
> log).
>=20
>>> However, after running for a while, the kernel is suspected to have
>>> memory errors. (e.g., a sibling machine crashed.)
>>
>> I have doubts regarding this setup. It might be faster (although one can=
 tune KFENCE to have nearly zero performance impact), but is harder to main=
tain.
>> It will also catch fewer errors than if you just had KFENCE on from the =
very beginning:
>>   - sibling machines may behave differently, and a certain bug may only =
occur once - in that case the secondary instances won't notice it, even wit=
h KFENCE;
>>   - KFENCE also catches non-lethal corruptions (e.g. OOB reads), which m=
ay stay under radar for a very long time.
>>
>>>
>>> So other production machines need to enable KFENCE, but it's hard for
>>> them to reboot.
>>>
>>> The 1st patch allows re-enabling KFENCE if the pool is already
>>> allocated from memblock.
>=20
> Patch 1/2 might be ok by itself, but I still don't see the point
> because you should just leave KFENCE enabled. There should be no
> reason to have to turn it off. If anything, you can increase the
> sample interval to something very large if needed.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/7c14bb40-1e7b-9819-1634-e9e9051726fa%40linux.alibaba.com.
