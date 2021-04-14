Return-Path: <kasan-dev+bncBCDZ3R7OWMMRBSGA3KBQMGQEZX4IBMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 57EC035EECC
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 09:56:57 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id t11-20020aa7d4cb0000b0290382e868be07sf2853497edr.20
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 00:56:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618387017; cv=pass;
        d=google.com; s=arc-20160816;
        b=dR2jyamEN1UWIHdB1t7pjldW6i51u2+3hpzAbe3On3iKgIcr/rYjlx35UY2PHfp9X4
         zvZ0blfQL/x/8x9mpnkrmJ5abmRmP2F/yQOqtHv2S8Rp/RN3ci9hT7zxLuynfLxRtnFP
         Tm9qfoP4Vc0BYJHqykHv/ZjADBUWK7mOECZ5F7uvA+W8MhtjKaZCR4xLhIrUt6i/FBvy
         x2XCQha/i5v7QW4WN6BiixkKSaFBvzO/ZDrJw5EKBtNFdZs8jFzdap0pSMDf3PB+SGcG
         NTYVuIVa5mowYvECvx413kBs6bTHgl8iVzgO8n4Xz0wzPq/1uJAiWAScF/4p+eZtpisu
         /k7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=NRgPgr1b4vvoS5oJ/vBYHHXNTkIPWSAdLv3LGKBXZpQ=;
        b=DSuPtG1owqSrcmCRVNPoF3EescoaqfVNKuhGYNPe7OPow1LsEovOy8tC6dLhFQYul5
         sj9NCXw1VHtx+qQrCLp/5viKR3vuGragP6Jz6cBld2xB5b2QM2vWarokO30gvf7QuiMJ
         RLczFVS3Oir9IIAOe8fo+82gZzdODE0pQMjHDYw/IT9MD9T2P8UUr6wQfy65dr1PUiUn
         7NvKbzA243W3Aws9Ux09fcJEbdFKSHHiXbgsSVR+t1OEV9luVJRKJaSiIFrrpTUGKh8A
         kdkgzipv5Hj+QyPuDA4QME6z3CSqpfX3akSoUOUdUyHQMB3Urnk/CmSVI74Lo1ggpCfN
         9FUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b=DclMOqzL;
       spf=pass (google.com: domain of efault@gmx.de designates 212.227.15.19 as permitted sender) smtp.mailfrom=efault@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NRgPgr1b4vvoS5oJ/vBYHHXNTkIPWSAdLv3LGKBXZpQ=;
        b=ITuB1HGRDkLNiMBHMTHEe9w18fhOVFFTgjpCuSUvYG5vVrVDtU8L7NyC7OnsE9vKMS
         c/FiWSGA2Xmuzw9onjlOgQpmpc/6Gvh4bRpSKl8E4tQ0L/8t1+m5l1bPGN5xeiMVggTQ
         hmZXzc3Q31QayQfk9oE31yRQjRlosjpQ0I7chBCeDAJyY2aeUIo3QEfEloDzpDS7YX04
         xEJAdGX6NCheDgYdUXjpkT9io5sKCstFwz/W0MISsWzvIiMJLI6x2wGk24+RXEkZ3QE7
         EjNJaL+NnYOfWBzuTvRVWZUKZFCusZLdtSCBQ3uIo0c/RfCLVgJzS6MCttw5yjYegkEU
         /X4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NRgPgr1b4vvoS5oJ/vBYHHXNTkIPWSAdLv3LGKBXZpQ=;
        b=qYfJfdK2iZN/pw+LlYSx74GKEVYYM9nN46TBiB00+4kY9PIvgx+Daaq5l6N7jUGStL
         R3Ud7eHjHACCTxTsfHLsn7a43G4eYQyPw+XWvX+mNvExjvCRKIUSCjdTcRQdECUEEyTv
         EA98JSmNAnh6gt8Xt9juDmMBojlqgtNaE8B8IMa9IhXUNheaGSGN4/J9yhh60VFeeBpo
         xenf1nsR2kgJaTxRDo3iTuWMetJPfKnazc3y/7B9n9nvpbPEd3NlTqESn337jv+MJCFd
         e3G/OoQOxXRHN9X6T7ZF1pnUbXYLIE64cQIwnfxAI5zeOkaBfD9/jwjuAQlWni5UwgIj
         5D6Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531H4Jl0mEP2XbfLOFFp2s9U7txE606f2JPJzzRu/jTjTAWaXtL/
	3tssvZWKNMpFRzHdceNQkAQ=
X-Google-Smtp-Source: ABdhPJxu4wdCRcpCdxfZl/OiP/CDdu8nC6yvKotnpDgFpwGfO156Qgx/cxjE3br2deU9cXOzy4+REA==
X-Received: by 2002:a17:906:f1d7:: with SMTP id gx23mr36254151ejb.109.1618387017086;
        Wed, 14 Apr 2021 00:56:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:ca0c:: with SMTP id jt12ls607409ejb.11.gmail; Wed,
 14 Apr 2021 00:56:56 -0700 (PDT)
X-Received: by 2002:a17:906:d8c:: with SMTP id m12mr13994278eji.347.1618387016264;
        Wed, 14 Apr 2021 00:56:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618387016; cv=none;
        d=google.com; s=arc-20160816;
        b=fxkjYsk0DBCbg7QqsyTbNjDBLVp7eXWwZ5cxVqwxR14hhdfcZlvFrPz3RJr/XrNyPS
         8F7CxIYxsTXc5NIBmoBKyjwq5Ui7IqlgybmhqjpnAtY7Lij8cF2/DMIkdl7fUiBtrmsl
         wGpXYsXbwvF/pF/5bVj2M4fQtq8KbLkI9yxWfBNzshhnFf2rZLmwleJVKfu062B/Q4Rx
         r990JCrD4QgUVTIZUH6D/T8PC3FRNMXmo8nrZgaiDWRrRITE6gRR6FZw4VftByiR3SNx
         dZsGgxbND3JaN4qBw5hYRvGe6X6r9S7/TDDI+s9rE4eViUjVg1PO0GC/Ob9GV9QD33f8
         KKRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=T9S8ULzCi0F60BJzmpyVdlBprPPk1MO7w9jt09FyFa4=;
        b=kG9joFfXGH4zLFU0uH9KoIcmLVg/ZGMDiCs1NWm+XEdHZdko2L34TsIDG2/6tM0aeS
         XHbNVBU0uXK0gozDB/MuH2ifU+cFXK0Lk58d4JAEq9198mXgbII4GDo8ADRssjo5QFy/
         M0EltlpeVyPVZm4f30/9im57hyTGS0Xzhz7QnxMI/SansLuuSNTG0Ep4s+oXsnCJyqd7
         kSQgRznf6eVEmLplLKF968eM27DWaWkLoUbdwpNn1T2ZlC73E1LYeXWPcp0djgerJM1C
         ZyU3rLOrbwlJLscyjMXGYErPqpPCtgwE7zFbJNidvCkpCMyM1rF0AA62TwRFyDWumHYa
         IK+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmx.net header.s=badeba3b8450 header.b=DclMOqzL;
       spf=pass (google.com: domain of efault@gmx.de designates 212.227.15.19 as permitted sender) smtp.mailfrom=efault@gmx.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=gmx.de
Received: from mout.gmx.net (mout.gmx.net. [212.227.15.19])
        by gmr-mx.google.com with ESMTPS id h1si41045edw.3.2021.04.14.00.56.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Apr 2021 00:56:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of efault@gmx.de designates 212.227.15.19 as permitted sender) client-ip=212.227.15.19;
X-UI-Sender-Class: 01bb95c1-4bf8-414a-932a-4f6e2808ef9c
Received: from homer.fritz.box ([185.191.216.50]) by mail.gmx.net (mrgmx004
 [212.227.17.190]) with ESMTPSA (Nemesis) id 1M72sP-1lT2pG16P1-008cGJ; Wed, 14
 Apr 2021 09:56:53 +0200
Message-ID: <d47e3abad714ddae643c7e3a10bbf428a65ddd17.camel@gmx.de>
Subject: Re: =?UTF-8?Q?=E5=9B=9E=E5=A4=8D=3A?= Question on KASAN calltrace
 record in RT
From: Mike Galbraith <efault@gmx.de>
To: "Zhang, Qiang" <Qiang.Zhang@windriver.com>, Dmitry Vyukov
	 <dvyukov@google.com>
Cc: Andrew Halaney <ahalaney@redhat.com>, "andreyknvl@gmail.com"
 <andreyknvl@gmail.com>, "ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>, 
 "akpm@linux-foundation.org" <akpm@linux-foundation.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Date: Wed, 14 Apr 2021 09:56:52 +0200
In-Reply-To: <DM6PR11MB420260ED9EC885CCD33840EEFF4E9@DM6PR11MB4202.namprd11.prod.outlook.com>
References: <BY5PR11MB4193DBB0DE4AF424DE235892FF769@BY5PR11MB4193.namprd11.prod.outlook.com>
	 <CACT4Y+bsOhKnv2ikR1fTb7KhReGfEeAyxCOyvCu7iS37Lm0vnw@mail.gmail.com>
	,<182eea30ee9648b2a618709e9fc894e49cb464ad.camel@gmx.de>
	 <DM6PR11MB420260ED9EC885CCD33840EEFF4E9@DM6PR11MB4202.namprd11.prod.outlook.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.34.4
MIME-Version: 1.0
X-Provags-ID: V03:K1:lOl8XRpuQSDP5jCLgTZRxrpHEEiYy6+1yubRgO/J/4je0GfEMvp
 h4u1jz185MnWrGanzgpPolJ7uRtTXt5qqFIqhhM1d6+LYPP5fT/GVY9HMJ68Kste03PBL8d
 lcdJJFJpcs++Ksdv9Sz30NOudW63ejXvLTCwdTkkcwArK8GxWn1Bjwz23ThTMH57um1xfBB
 fJRvtKmBBfBmrUI0o5SOw==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:siDEEibQxqo=:EvtHd77BMBR0tdMlJIOtUs
 OmiK5HRrlJfX7CW1iIvdyOTDjOpD3MSOgDWwOJXPFHHwzL2NaAbt5E/FBHMNKDKUnxSOGHZDj
 12FJ2xKsK6P15mqaB2rykElfTDOyi6MSzcfmeaWGh7AvCMFzXs71fC2v6mktcM9gBNW3HRK8i
 7E2m7zB83moDV0deKWzsbvxgzyZ4yfwhLFRtOS4BM8gFTaVxsHLWtOMmI+VZ9nxfSqNha4CHg
 fJNgaOWcmvfIU4ImMFmW1i3IOYPxhFrIHfxfUF6vX9Vq31hyVjlpw+lypWv6FR6J0QKzMCGQY
 vEOqPgTOkBHbZtDpin1n8l/waME5m2wRh9FrOlfb1LK9qxMoHx/0nzr5S0t4Os0m9K30OJCRj
 JrR/DfR1yxVJTWyMk3VyLMDuEdztHXQMBjP5CN6RGy3hTMueNOKyX4WOJwP6LDo94cmDh1T7U
 0XCsvf/ggBKUSNiYPkBCdh7hpkF4wIwqvnku12fyxaO2nsMsvOQORIdX/G6Zn91nd6Ven3P2y
 p7ADfd+5JBce6ocSuY6dpW9Wx3Gu/lzdf7Y7/z6CcsWdMtv/F1+JBenUJJTg7um/EzErMHr57
 g1l70dUicQjFkrf17PpMpiZYEmY+lSuqIpXnpVFtPWs4jyeyd4Jtd4Ol7/negh04Cf9zzk0CN
 SItsFcxBEF/G5yHvCxtxURfJbBFttVNtuI/r/Sv+uzadlHt5rDuD4HmXhVvlj+Xrbz9KEAkWC
 A3TTValnN9yQ4pecWCaLgLCi0VsHVfRbz1U8Z0q7jYc2Prf3S8GgtMDshnxzcGynXux21ICQD
 x1P16Xpe9mLTCnhokC1XSWJh4XIT2Scq+wwS8YkozM8lLtwB/NaSuDeEbFIWIOdDLr+Qv5Fig
 3U1AGZWAi4W8+/fpqTjWGHmts/dZT7RrFkjQcdudqK7tBcwBDrVOibAcP7kF1AIrNZwXJtr3o
 kr2BB5ZT9LeflNSq9dRf5WlKCH/SaGK50mXoGX4/5rVdJfsw6bfN/Za9Nt3/JoXuSPx3T0lpn
 ypyOX85OKna/6HSTgVMOerIe+x8Kf0GUvcbtWp7dtAofZLAUX5jJWgHQGx7dOkjicZedaBBKI
 LpOWTzTkjzBLT+gIuiI11ddfx+LNaqWlMITYydwVvbdX0uVF2Mf9LXlZ8TOgwoQ/an799ozG5
 vtnofUFVLZ5ZdIpRlNrb8ZgqnORD78NZGeePRbW1vmWSzl9GiX4RTI3tXiskkbqxPvSb8=
X-Original-Sender: efault@gmx.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmx.net header.s=badeba3b8450 header.b=DclMOqzL;       spf=pass
 (google.com: domain of efault@gmx.de designates 212.227.15.19 as permitted
 sender) smtp.mailfrom=efault@gmx.de;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=gmx.de
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

On Wed, 2021-04-14 at 07:29 +0000, Zhang, Qiang wrote:
>
> if CONFIG_PREEMPT_RT is enabled and  but not in preemptible, the prealloc should be allowed

No, you can't take an rtmutex when not preemptible.

	-Mike

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d47e3abad714ddae643c7e3a10bbf428a65ddd17.camel%40gmx.de.
