Return-Path: <kasan-dev+bncBDZLNOG6TMHBBEHD5S7AMGQEHELSWTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 79344A69A8D
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 22:05:22 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-3d43d3338d7sf2582805ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Mar 2025 14:05:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742418321; cv=pass;
        d=google.com; s=arc-20240605;
        b=BTaSVK+tZzqv8nj3rb3TkD/02PARePvv0QEMwFIKmQDLx9DWL6dYg8jaItuHcqyvFT
         i55KyyBKL5l7JPv5TgKCul7rY8ahmnSImTTywWpD6RUg7FcUmdFV6t1jpO3z4/7YsVcU
         n35UAmSP40QRRvM1RvAmQ9W0ex+eA7FycitjOkgziZ0AWSfiCAeJio2HK2VKp2MdJHcP
         mkxrPb3U6nIAK1+YhJGa3FZwv+oreyPTAK78vsPcyAkzKwh+bm+EyfTCgTno/USwk6G0
         j4m8EE9cz+4TX8rW/Uu60rRB64N6fmYwJO/xOz9AS50vMhqDZnxdjOQAldEHOjAf8eAC
         pmWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=Zq5xTeiiuVHfiSZ2LoFE1KlbZ+QSvubpVfwOarevTgk=;
        fh=hIVvaxAPW/d6C7aj8nTCxIU9CPpNCCCXuvy/KGF7HEo=;
        b=hA26A+Z7X8SxTkkum1oV00o3PGyMsHqBM5YIc8RbC1+IrV6OZZQ8f3YDBBY7ZMPVTx
         Q85ESL9h4m1qk8ir39DW1S6jK0/SClEaVLIXjpSJg5eMeDt79cJNI8ikCrMFAxAt+yJp
         vcJOn8Yi/nRJNrbWi+N6VJHQXlVCR5WWRlbeR328Jbh4qzLzvh5AZQUnRfZofa3HP0BK
         mTUBkDzuI6xb14tyRylTJ+GynXG5LzXTGMhk22pvnYUBdlSXAauaZO4kmZXAyrFESDg+
         TzpNvDgwHtMMhyuVzzvFo/7r7ldj4uxxV27Z7tKQI2uZnYINqF/gcH+c/9OOeeXsIrYc
         h4/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mojatatu-com.20230601.gappssmtp.com header.s=20230601 header.b=bOZ3YkdS;
       spf=none (google.com: jhs@mojatatu.com does not designate permitted sender hosts) smtp.mailfrom=jhs@mojatatu.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742418321; x=1743023121; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Zq5xTeiiuVHfiSZ2LoFE1KlbZ+QSvubpVfwOarevTgk=;
        b=FGkkBgHzC3on6MMcy678elgETRCssBX99+YPm++gJHKmgVVfepXRjLjNkZlojTllwe
         FqaePbXhkSJU3d+OyuJ7qwIYm9rXHkyj2K4intZLzwzfrxJQhfp9WV+kEtIEPGc6kjvz
         g8BipVeNPQ5kpZ19r12a8mdEv+52ONg6tUwt51o08HSPElxDj9q6+78jQ81ZV0xwReYk
         tan9NuVDRC8ndRpg46VTFtcnpynnWQ+8pioqQRXuXeqTb56f0wzZgLY5mJn1AP5SRhTE
         aS+4mOi/1tpmaSEsqIO8tHPAn9BNred/e6Wj5CietYpwIf6xOfWbsHTUu8sPEYMubICG
         +lsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742418321; x=1743023121;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Zq5xTeiiuVHfiSZ2LoFE1KlbZ+QSvubpVfwOarevTgk=;
        b=ItwV4tF0LZIHjFoQitbmjy+OQRrVhyyw771/Walov4SjpVRnjnn3KNOESBXkFupGSv
         hvQCRW/yGFH1izMV8R3Lyc8O273H7L3vZU6vzZf/vMd31kjA8K1/x7J4mTKNuOO3bacL
         nO2NsEYToKwboHG3Sr7Wck32fGK4Qc2zE3Ere81eNRFPqt91l89Dukly/u6nBuFgiSuO
         6MkIyjaVyblA2DofLRfiZCxgUj15Zoo9sa0EuyOYYEQLUm4IM/fd3/f5uhQ8GoA1X2uE
         qya0Kea0hmOtn1d+ss8HHGFTudk9bYHdd1PolcFxps1rPMmgAHPcKeT2X9wpoOdFRkUt
         RyhA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWDjtBQl7Vkfid6UXL6JinINe42tPKn+i6ETFNeXOwEn5VZ05OBE0VhlMsJD7K14xSP+bxe3Q==@lfdr.de
X-Gm-Message-State: AOJu0YzLD9jELRE35eXxok9By/Q6QSfAtvQPEXrQ7yJzVzcjTJHQB5ta
	AX8Yxfndl4JkH3v3GabBJNYZWc6qspIF00RQkNu1f8AkdeGGdgpv
X-Google-Smtp-Source: AGHT+IHdim73j3fJuL9NwqjietBfYHVly1M/9TRR9hRNMbNBbK6eHaZrhDo+7E8eZWIXd28sF19OSQ==
X-Received: by 2002:a05:6e02:1a4d:b0:3d3:dfc2:912f with SMTP id e9e14a558f8ab-3d586b2fd2bmr47933625ab.7.1742418320916;
        Wed, 19 Mar 2025 14:05:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAILY9fav510KIc7wUPFSJYOj08ioxPtSiMkqwxJ1wWkbQ==
Received: by 2002:a92:2c11:0:b0:3d1:a26f:e248 with SMTP id e9e14a558f8ab-3d58ec027e6ls1874895ab.1.-pod-prod-05-us;
 Wed, 19 Mar 2025 14:05:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX6Oo+UkhiRH/JqgZBN88LV63br7CPQFrtOm4uuVfvNy3SoO5s3lxF/4IeOAm8Gn24mJkaQQCvaXdo=@googlegroups.com
X-Received: by 2002:a05:6e02:2589:b0:3d3:fdb8:1796 with SMTP id e9e14a558f8ab-3d586b1b1d2mr44784055ab.2.1742418320106;
        Wed, 19 Mar 2025 14:05:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742418320; cv=none;
        d=google.com; s=arc-20240605;
        b=GGBfE0OXwhppciPyxHL3gIHEPjGXe+USgxqCP6zWzbOrfywZQNzrzxsikubbInODk+
         E1NBzBd5ScP/YbIJC2vLqWQ+D0uw9nVc/EEpJdoZP1Rlqctp15nW0eY0Wmi0hj5Y2xfJ
         t0IRqGvOmFnScN4YrFriYTbqH6GrPB9DLi9+o3zpAXnGgT4d5tGFv61qw4wCvGJ90nYI
         EEedDO2J6Zh9OCfkrHXH1kW7L3m4JDqemkpTIDfc89WdUk991or3FXerEHBev1TPb0e2
         EczexFaijvoZg9pb3KNf6LDAu1RFMU2GPWioCyqmbmDzQiakS4iX7uLo/n2OhLmxq3aT
         oYsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=oqBu+kgYhUgJYB6L1gDuORiFdkjW7KdzRSCRaQJGoA0=;
        fh=gecPtBhyU09yPkmQELJirETmbowtpSV21VKyqFLGOP8=;
        b=Du9TKB8Nrd1gnkDJN4sRignnG5+o9HJZFRPPwy/9kLv0f53d0T35ttFQsOXdTCDyC5
         gj7RAGynDphYtyB4GQGo74MEOFS6r5ATBc56+mwiLvu84UCv1EQzhuWdA+eb1paA+bH1
         0vnQy+5pXem4AiNLowx8fvP3pQmRLFyyikuh+Dam3fHDqG+2ADb1JSD/9sYQQj+ztF+5
         D+hCllUGSPo8HVQ3va0W9Er6qCfFyGQXukri6nXu3rHEshI8Bx3KiqC+8ovDe4k7l1e4
         r85AhzLqeQbR6KkFVRxS6S2LyVl7hzXIoiBr/4lVGvQpEdsk2K26NvoZo2Pf9Da3Qg46
         vQlw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mojatatu-com.20230601.gappssmtp.com header.s=20230601 header.b=bOZ3YkdS;
       spf=none (google.com: jhs@mojatatu.com does not designate permitted sender hosts) smtp.mailfrom=jhs@mojatatu.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x632.google.com (mail-pl1-x632.google.com. [2607:f8b0:4864:20::632])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3d47a86da18si7852415ab.3.2025.03.19.14.05.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Mar 2025 14:05:20 -0700 (PDT)
Received-SPF: none (google.com: jhs@mojatatu.com does not designate permitted sender hosts) client-ip=2607:f8b0:4864:20::632;
Received: by mail-pl1-x632.google.com with SMTP id d9443c01a7336-22349bb8605so446695ad.0
        for <kasan-dev@googlegroups.com>; Wed, 19 Mar 2025 14:05:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV0wNfkEpQ5ML+gI3AJZCzPhfpGKohRzIv0hK1XHKg8jvTvZTcrEHQDUoxVW5TuG/D7uclyQG+GVPA=@googlegroups.com
X-Gm-Gg: ASbGncvjcD9tWzNoKkbNpopu3T254TMU2g/2p91JDZPsA7fdMNwQ+8ulKQs9ubJipRd
	pYB2CSsDLUDli+zoqKOlXCSAZ/SKmJMD32Qi1zgd4TaqITet/AiIJcsyGo+DcBxmx9zedREVrNa
	tA8Ee1l4UaN3U3l76gbiw20k1eyw==
X-Received: by 2002:a05:6a00:4608:b0:736:34ca:deee with SMTP id
 d2e1a72fcca58-7376d60f54dmr6415226b3a.7.1742418319237; Wed, 19 Mar 2025
 14:05:19 -0700 (PDT)
MIME-Version: 1.0
References: <20250319-meticulous-succinct-mule-ddabc5@leitao>
 <CANn89iLRePLUiBe7LKYTUsnVAOs832Hk9oM8Fb_wnJubhAZnYA@mail.gmail.com>
 <20250319-sloppy-active-bonobo-f49d8e@leitao> <5e0527e8-c92e-4dfb-8dc7-afe909fb2f98@paulmck-laptop>
 <CANn89iKdJfkPrY1rHjzUn5nPbU5Z+VAuW5Le2PraeVuHVQ264g@mail.gmail.com>
 <0e9dbde7-07eb-45f1-a39c-6cf76f9c252f@paulmck-laptop> <20250319-truthful-whispering-moth-d308b4@leitao>
In-Reply-To: <20250319-truthful-whispering-moth-d308b4@leitao>
From: Jamal Hadi Salim <jhs@mojatatu.com>
Date: Wed, 19 Mar 2025 17:05:08 -0400
X-Gm-Features: AQ5f1JoRzWT7Z7j0VHgURamunfPE54qbAEp2C2JXfoZJFMWPsaolLFCk6I2GSlQ
Message-ID: <CAM0EoM=NJEeCcDdJ5kp0e8iyRG1LmvfzvBVpb2Mq5zP+QcvmMg@mail.gmail.com>
Subject: Re: tc: network egress frozen during qdisc update with debug kernel
To: Breno Leitao <leitao@debian.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, longman@redhat.com, bvanassche@acm.org, 
	Eric Dumazet <edumazet@google.com>, kuba@kernel.org, xiyou.wangcong@gmail.com, 
	jiri@resnulli.us, kuniyu@amazon.com, rcu@vger.kernel.org, 
	kasan-dev@googlegroups.com, netdev@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jhs@mojatatu.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mojatatu-com.20230601.gappssmtp.com header.s=20230601
 header.b=bOZ3YkdS;       spf=none (google.com: jhs@mojatatu.com does not
 designate permitted sender hosts) smtp.mailfrom=jhs@mojatatu.com;
       dara=pass header.i=@googlegroups.com
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

On Wed, Mar 19, 2025 at 2:12=E2=80=AFPM Breno Leitao <leitao@debian.org> wr=
ote:
>
> On Wed, Mar 19, 2025 at 09:05:07AM -0700, Paul E. McKenney wrote:
>
> > > I think we should redesign lockdep_unregister_key() to work on a sepa=
rately
> > > allocated piece of memory,
> > > then use kfree_rcu() in it.
> > >
> > > Ie not embed a "struct lock_class_key" in the struct Qdisc, but a poi=
nter to
> > >
> > > struct ... {
> > >      struct lock_class_key;
> > >      struct rcu_head  rcu;
> > > }
> >
> > Works for me!
>
> I've tested a different approach, using synchronize_rcu_expedited()
> instead of synchronize_rcu(), given how critical this function is
> called, and the command performance improves dramatically.
>
> This approach has some IPI penalties, but, it might be quicker to review
> and get merged, mitigating the network issue.
>
> Does it sound a bad approach?
>
> Date:   Wed Mar 19 10:23:56 2025 -0700
>
>     lockdep: Speed up lockdep_unregister_key() with expedited RCU synchro=
nization
>
>     lockdep_unregister_key() is called from critical code paths, includin=
g
>     sections where rtnl_lock() is held. When replacing a qdisc in a netwo=
rk
>     device, network egress traffic is disabled while __qdisc_destroy() is
>     called for every queue. This function calls lockdep_unregister_key(),
>     which was blocked waiting for synchronize_rcu() to complete.
>
>     For example, a simple tc command to replace a qdisc could take 13
>     seconds:
>
>       # time /usr/sbin/tc qdisc replace dev eth0 root handle 0x1234: mq
>         real    0m13.195s
>         user    0m0.001s
>         sys     0m2.746s
>

Could you please add the "after your change"  output as well?

cheers,
jamal

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AM0EoM%3DNJEeCcDdJ5kp0e8iyRG1LmvfzvBVpb2Mq5zP%2BQcvmMg%40mail.gmail.com.
