Return-Path: <kasan-dev+bncBC7OBJGL2MHBBW4VQKIQMGQE4KBY2VY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D5B74CBA4C
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Mar 2022 10:31:10 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id s83-20020acaa956000000b002d41cfd2926sf2825591oie.0
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Mar 2022 01:31:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646299869; cv=pass;
        d=google.com; s=arc-20160816;
        b=OSwSfT1OIXlIaPxDVTWnRnww9/gpQpzsRcvJqrL7xvDh3Rg4W0ITwB52eVpe7AhruV
         DtTaJ+LW0GoyQS0mTV8IInw2ySCdh1mmxjJm+kokPDmE0iHzFtIo1vnSxYWDk/s/DP7J
         QNTDaf04WBc/gJ7WUn00KRe+GimnsQLw7NojBJ3uDd1cGTmIyxa99TCFt7SGBjcjjAn/
         TYTqLsGtD6q68mTT7Rm/5K/XJqqxcVemlxNwsch8Opmx75Ty9ekSiXDnTKwKwcXf8Sug
         eKolXEkRG8ghC39ShrN7g5n3hKkNrqL+nisHXwdBz3VqDErHtTr14sh0hSg73YVn1Xr2
         vx4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Mcn/laZTKPtIP9A801YlKuD0/aVQUvzvYIfqAfLW5Fs=;
        b=vIkteN9yM+5oQQ4L11RqGNU1kEtDgxrAUNM9AYIQdpGTHnqVv8AnoPhEijSHeUNv42
         t4hlSVD3ABwsdz2YBkG89LcBww6NZqu4VEloPWTvg3ZCjF0JkLSrJ622NWwnBpdH+6Wn
         GwZI5u9p6TKht1eE8NoQO3RsJLYxUnT1bUItJUh1aiU+Z+ZSWAuJN9VAdmCn5mYCpGte
         p6j3Mh3zt7XM2f7M+yxPjkpJYrA1aH4KSnJyWKduCQhkZTss9oH9Tn9bY/0VG2xUMtHv
         s2F9oMTuh/3LdUTApeqaMqJwy/g8cEeKYgELX/leP3ZuPo8aelu/NthB0Lqd4A9ObEB8
         zWBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=URDf26+d;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Mcn/laZTKPtIP9A801YlKuD0/aVQUvzvYIfqAfLW5Fs=;
        b=IgdLvny2sf4G4Phk5GWOEiZOV4uD2c4uSa7TTD9HeT7nZ76aOSHWI2aoensxBa8uW/
         iBDxhKLoO6Y3JWraalkZX/vTU0uhY2nxf50I7bYLEYBeWTz3pXNoC9cT4+kwZLAwXoo6
         cm4HymrxcOANBCFgbijhLaZU5RC2cXf2C2iLlgybvwjmJzcW1xp9XXwMdqehoexiC/Tk
         8jwFFdMujopwHzJGt4OFPOcqb4KnOZKHM3Qmh/T15l8gU58ge8AlnD55/7IMuU3hXWS1
         5f95z+FnYJaYMTXnQCpDx1gNLUIekY8jLy/43EzB1eF6dTlNuvqibi2uVeF8erYtVr23
         7QHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Mcn/laZTKPtIP9A801YlKuD0/aVQUvzvYIfqAfLW5Fs=;
        b=qXvZ7HqKzx2+2szeCM7Qzj5vhJA5GPq3odK4PencxSjC60sNZD4SJWXvSLs5LvVe3D
         VA27p1ct6E7z2ov9FvGi39aTYELXXcu8n84/+ed9rI0fDyU0EOgihNui/syZZZOo74NS
         ShPmWtftHZ4yIWrC9uQ21+vQWsj9hsMIZZG/CjsNarNGV2D5LznDOVheo6zA/VibZNj5
         zWQ0lUDx8yGU1aANnYElBE9k6LzwXEoSp8Z5CK41MvSZRr2Ie7ElWA2BqL+6djV+roxE
         ZOE4jrbgslIPqDxaSC4Gc2CzSJJkKarJmV43ROz296CxONQ+ayDl1365FpcRey4IFdT7
         VZAg==
X-Gm-Message-State: AOAM533vrffgFQVzzCEP/79Mu2WgQfK/ph6iTmkJHoNCDCVOQkZe+dBA
	T/wJ3wbquO1TdiqqyttL5g0=
X-Google-Smtp-Source: ABdhPJxEJ7vFx9SHqcyh2X1S13jCzNF2lz3D3LJvLUmDitejk2F/HadnbxjyqD1Jymad7waOnfsFgQ==
X-Received: by 2002:a05:6808:2095:b0:2d5:328d:f61b with SMTP id s21-20020a056808209500b002d5328df61bmr3563462oiw.9.1646299867242;
        Thu, 03 Mar 2022 01:31:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:21a3:b0:2c9:ed8f:24aa with SMTP id
 be35-20020a05680821a300b002c9ed8f24aals624972oib.5.gmail; Thu, 03 Mar 2022
 01:31:06 -0800 (PST)
X-Received: by 2002:a05:6808:218e:b0:2d7:6418:a7ce with SMTP id be14-20020a056808218e00b002d76418a7cemr3584214oib.34.1646299866808;
        Thu, 03 Mar 2022 01:31:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646299866; cv=none;
        d=google.com; s=arc-20160816;
        b=koVaOcks6yVnne0El1xGf3iJqB1JWLFp3jZPudpoXXR29iXw1b+8CGLPfXXSNv3N47
         iQPNgMSYoUYD8XX9LXxNIGCoeIXc1MxAwC10J+RcbEb0+jylvH1ORUx5WpKD9LWI0J7h
         ZvPtlR+etlUVRdKWd8LDd3VC8Ns5O1gKyzGnBhis2rLPqOUvOXtOIroh6V63LfSkNSUj
         eXw4gHwIq4ebqBo82PUqFNswY+3zzaLg+3wOa+SQojGXiRsmaQxcUleg8usmRnNOOr0R
         ow2SJkVwKQCruxLoTGLLTZGdwUt+Ik360VyR+98ZdOmpbTp8WPPXXKPX/T6W9FyOAlZi
         I7eA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=w3iW8OgIGRJkwzf0fEpKvBUUqPlzMNEZGmdG3QGabg4=;
        b=WGZWPHKNdb1f2bwzd7HrGl5Va4Vfl72IRLrp2Iu+eaMHKiVu+i9siTnq2mJJX5svUT
         jZ7dFKtQIuP9zNCMoXhw8JNnxHbGaK1xlCGf2tkvrAQ2MTb2qn8kDP8rhVOdqujReUl/
         AWmla5PVNeQV1NyajskGOOoudbpOSzbYqaXdZoBxEaG15TtjPy/+sjBJNjam7lNVKzhc
         I2EtH70Igc8z2mhSvQxDEhagth9Qmyd/sg4vHfZ3yW4CK3irBytavuoHkIYuvHFK/6z/
         rFkYFGCwga2mYUPScmphJVdWrRCL/h1T3GJnnylQsuCa3iUIXvfmx6nX4DdY1SApPo5Y
         jnFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=URDf26+d;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb36.google.com (mail-yb1-xb36.google.com. [2607:f8b0:4864:20::b36])
        by gmr-mx.google.com with ESMTPS id r128-20020aca5d86000000b002d62816075bsi161489oib.2.2022.03.03.01.31.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Mar 2022 01:31:06 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) client-ip=2607:f8b0:4864:20::b36;
Received: by mail-yb1-xb36.google.com with SMTP id u3so8966356ybh.5
        for <kasan-dev@googlegroups.com>; Thu, 03 Mar 2022 01:31:06 -0800 (PST)
X-Received: by 2002:a25:a4e8:0:b0:61e:1eb6:19bd with SMTP id
 g95-20020a25a4e8000000b0061e1eb619bdmr34271771ybi.168.1646299866132; Thu, 03
 Mar 2022 01:31:06 -0800 (PST)
MIME-Version: 1.0
References: <20220303031505.28495-1-dtcccc@linux.alibaba.com> <CAG_fn=Wd5GMFojbvdZkysBQ5Auy5YYRdmZfjSVMq8gpDMRZ_3w@mail.gmail.com>
In-Reply-To: <CAG_fn=Wd5GMFojbvdZkysBQ5Auy5YYRdmZfjSVMq8gpDMRZ_3w@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 3 Mar 2022 10:30:30 +0100
Message-ID: <CANpmjNPBYgNMzQDKjNYFTkKnWwMe29gpXd2b9icFSnAwstW-jQ@mail.gmail.com>
Subject: Re: [RFC PATCH 0/2] Alloc kfence_pool after system startup
To: Alexander Potapenko <glider@google.com>
Cc: Tianchen Ding <dtcccc@linux.alibaba.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=URDf26+d;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b36 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 3 Mar 2022 at 10:05, Alexander Potapenko <glider@google.com> wrote:

I share Alex's concerns.

> On Thu, Mar 3, 2022 at 4:15 AM Tianchen Ding <dtcccc@linux.alibaba.com> wrote:
>>
>> KFENCE aims at production environments, but it does not allow enabling
>> after system startup because kfence_pool only alloc pages from memblock.
>> Consider the following production scene:
>> At first, for performance considerations, production machines do not
>> enable KFENCE.
>
> What are the performance considerations you have in mind? Are you running KFENCE with a very aggressive sampling rate?

Indeed, what is wrong with simply starting up KFENCE with a sample
interval of 10000? However, I very much doubt that you'll notice any
performance issues above 500ms.

Do let us know what performance issues you have seen. It may be
related to an earlier version of KFENCE but has since been fixed (see
log).

>> However, after running for a while, the kernel is suspected to have
>> memory errors. (e.g., a sibling machine crashed.)
>
> I have doubts regarding this setup. It might be faster (although one can tune KFENCE to have nearly zero performance impact), but is harder to maintain.
> It will also catch fewer errors than if you just had KFENCE on from the very beginning:
>  - sibling machines may behave differently, and a certain bug may only occur once - in that case the secondary instances won't notice it, even with KFENCE;
>  - KFENCE also catches non-lethal corruptions (e.g. OOB reads), which may stay under radar for a very long time.
>
>>
>> So other production machines need to enable KFENCE, but it's hard for
>> them to reboot.
>>
>> The 1st patch allows re-enabling KFENCE if the pool is already
>> allocated from memblock.

Patch 1/2 might be ok by itself, but I still don't see the point
because you should just leave KFENCE enabled. There should be no
reason to have to turn it off. If anything, you can increase the
sample interval to something very large if needed.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPBYgNMzQDKjNYFTkKnWwMe29gpXd2b9icFSnAwstW-jQ%40mail.gmail.com.
