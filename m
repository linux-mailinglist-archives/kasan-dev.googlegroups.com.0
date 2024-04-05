Return-Path: <kasan-dev+bncBC5NR65V5ACBBAMWYCYAMGQEUIEA65Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id AA44C899FB4
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Apr 2024 16:30:26 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-4140bf38378sf16359155e9.1
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Apr 2024 07:30:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712327426; cv=pass;
        d=google.com; s=arc-20160816;
        b=JCiU3sHLjhg8jmHaMlcJb8FYpNDUmZa/iMao9iDb0hmOP5yjlhHY4W0bMKE5j4S6ad
         KwnL9JJGr5WPBTilMhABp7BZzhtfe4Ku7OafQLo7bFNatSScfjZuX2JcOz4mD5YlnSEk
         9TiK0F8CzVSY3ro+5tUViKcyNps3F/8mA+QZlBKhAoeUQCZVgNjcjw4uR1A1h2yQ5AZu
         05+NaqX4CZOBBpnRS0GaNaQhD3FU1QB12YBLuQXjPCsNQ4XuZcnsznIK4Cb0c3qqQKu8
         cBwtZ6gEOJapHfLVv2qVKz3HCm6LcsceOQ+R3frVc1lM4UuQfDpHrO0W5yUQpb8akgIH
         9Dog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=qqPM16USLv8SNKWWPxphWXje+Kv8ZAWfhtDEWQzJxzk=;
        fh=T2l1PHdonvg+eXXqTcXETEysqDWfSR7koxP3sVxFrD4=;
        b=wWz3QHG0gWY5ittSW4SnzL7oImdbgaCfuZ1sDt80szPflvAGYLLFmptfm2+GM86Hdh
         iZGnYfwgH6UkXxPBRYSL+/bTirn11VXxZtwb1ODY/3qhSWgN3b3RBxMkp3EpgLp1wDaA
         I0ZPm2Nzkw0xj+8rtymROYDRE9vU019YiS6HPpxTh002a+eMhWkDEAkcFfYkQWpdcpJM
         EmXRs3NcZGYOH0OUdBtstLV2I4Lofaiqtt2k5cqCy3zEPK1sR2xKD0bNpoCKxHC8alav
         uyzMXy43B43tOrLmmVpDoOtn6KJVgHKvEmvEPhRMNwjYms9OId0jw0RnmHcFyXS/w5DI
         PLlQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Xz7lRArN;
       spf=pass (google.com: domain of klarasmodin@gmail.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=klarasmodin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712327426; x=1712932226; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qqPM16USLv8SNKWWPxphWXje+Kv8ZAWfhtDEWQzJxzk=;
        b=tD6/xBWcP58J7UYE/n6bJ231svOIkB1M3ecp/G/BLlarqsx+ho7/16tQGcRmS4w/IQ
         7ncSjb5xpSPbtIq6Py+woPdtjd8iZ4+AHVjJqSvFGM1Jxn2V8KyhQ8RvpW3IsOTS41jn
         C0qwYGXSy5xVK4exLxGYlU1Myjdt1QrFZsfm+Mu/doPN3i9d2EV/BbJpw5BJG/Bwb6yC
         8svwLvnQ924x7EwCSAUOT2CjGPj6Rm03Uin27RJUcU8WxliBYJH4262sEWSxRTVqFghw
         nPZRSGTaFkyIrgF538LAts0mrB6jExlDKUbXPLrUMB9j279UkPu+Kfj6iyRBlCSQnPlU
         5KUA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1712327426; x=1712932226; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=qqPM16USLv8SNKWWPxphWXje+Kv8ZAWfhtDEWQzJxzk=;
        b=k3Tzq0KjJegvgQ7d3Pu7CiSOfN+c9X3JpYKK/UU7ZCcdw3NSGlu8weo9Aybe07+nWy
         Bt4nijEYQdSlXANG8X3J1G2d0T1xyg78HNwn67X7IwJtkYLPJNmj6faI9TaE5ZH23R2y
         7iotmb7rm+t6IuIySB2ExpOZ94erJoTCfwikfd5muUQobbrLyTli5jFCrEj/pC+Konk8
         cXRLHJ6To9C0Y20zjvKC+VT8W8ZxwSJf6BhGz91kLXtMw/CWbQ2RFDG35ncCrbVpBgv3
         PjpH3Vou94gewVCRroxW/WCPvqzrGp4u/3mJL83+lXK/EGd+g5xNTwlEM0EG8PDaN5rH
         59zw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712327426; x=1712932226;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qqPM16USLv8SNKWWPxphWXje+Kv8ZAWfhtDEWQzJxzk=;
        b=hGejOrDxPU0HTcVPMGNf7geZRHf+bmz7v96z/2nWPFGzfQVwdnPWXcXftFwVdpIDxK
         m4MRJJjZMwmitq3xSE/WYhBzUXHHQtqoAmQ7rLi06qyCKoZd/lcfZry7wuGmm/y/ezAs
         KlCtlW3HMBbdPcE7tCQko1FnTbEJTfIvt5TCrHmFoyzZ5qcPD40xTSvHLllVnsXdJE3u
         ZclZ66UX/87txPaIt1iybjy3oZfcYOJt+iISN5QANX/8RiGa83Ps4wkPoS8bOYWJC7Yp
         bwbU9pE4xi5aNTI1LWeprxpgCpss8Td/v51SrurFuKjYX6dRtE09ZcEW7l5W9js1jy5W
         xnzg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVsdnjkWUbGkmfkhvAe+/lESK15xBCsC3270L0CvR7P7jky0iE4BE8nVbpZBIdGRvzufy4Lv8ZSBflZy4I486wQdV07QWEFIA==
X-Gm-Message-State: AOJu0YzNJ2Fp6fzfn3jJrdEqUM20JQ0s+tKmCt+oKhPkvYpl1wYAzxpT
	3gG7S2PeiuIWdUOYDWXBTwtjnhemPGH5qcXT226UiWVvt50T02DT
X-Google-Smtp-Source: AGHT+IHBisH4tTBwNk2o1ZHTprNxFqBXY2pcd9WnP+ysIRgUWSxTzcFQ4MvGwc7kh61q6jdGHMGaXA==
X-Received: by 2002:a05:600c:4589:b0:416:2b2a:7f9c with SMTP id r9-20020a05600c458900b004162b2a7f9cmr1688122wmo.26.1712327425678;
        Fri, 05 Apr 2024 07:30:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f10:b0:416:2ef3:446 with SMTP id
 l16-20020a05600c4f1000b004162ef30446ls202904wmq.0.-pod-prod-05-eu; Fri, 05
 Apr 2024 07:30:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVckdx1iXk3WFF/2eeZTGpP0K7rMbUMF5R7V0EMy+zVsNeCJ55OSzACVUkOMNC4aMRt6p62Gnj5Wpaul4ZiJK8h9XgBKpK29sg+PQ==
X-Received: by 2002:a05:600c:314f:b0:413:e19:337f with SMTP id h15-20020a05600c314f00b004130e19337fmr1775823wmo.22.1712327423607;
        Fri, 05 Apr 2024 07:30:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712327423; cv=none;
        d=google.com; s=arc-20160816;
        b=P9sxWqhe474RNathUbBQnWFZUFTSaYE3YK33Cbo3PsSsDeNCVHp8AVg3Sidvbnk1Et
         Uw9AWr5ymubgP7SwfC2ZfJQSqpAWQOMaq+psrks4zX6kYsUV4IjYnU0Jh2F4vc9GAh1i
         fWzwEO248pdiKKX9JzKhu2fbScWA/KuDXl3eTRk/ZIOdpyI7NTYwq4flPcbgjaBNIikA
         uLwzY1+XFCA6amp5rAYmjEa7Mmv32jBjq17MJjgsFdj31MEzHk5iMQe2aeM3bezFW0Df
         IBGzPnPJvJhM6oHiKRDbIoFK/UPZdyQib9haAHdIeI79SWII1H/K3oPS1IrZIvUqxmh4
         UKqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=/hnq3sCt2H7lY5oSS405R1id2Z+jwtM4OI26amI8Aeo=;
        fh=V6XB/OKo5CEifSJbek6kdVP3ReDDGB2UcMamLGwlt4M=;
        b=C3itWOGAEqtHzSdL8Y13YPLJJdVLiJsY+pcP6FbOcw59BHZuoJJNO1u4CsP/EzdCHU
         nmWRQuns/pLQrovhyAEkCb6yYx9XuBANk79jokuU+vEnmSGawX1CNPqW1c/Znvkry07r
         cqYJKQ8TUmn18IAyOekzfkWb0jOx7NBBFbiRNEDYbnh/gA5ECdDw+2Q3m6sH+UmO72yP
         sOIEV3bc3GxIlr4eEF7eew89BaroUA3qIRQDR54h9dnXt870KG6OOZNpBk8VpFDWQxJb
         9eCxWSk9p7TvUBinNrtAdaQOLLNcmG2BNu9wgSeSGMZeJwV8slXKid66mJvuxUA1y670
         Qu5A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Xz7lRArN;
       spf=pass (google.com: domain of klarasmodin@gmail.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=klarasmodin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x12a.google.com (mail-lf1-x12a.google.com. [2a00:1450:4864:20::12a])
        by gmr-mx.google.com with ESMTPS id l6-20020a05600c1d0600b004162ab7d66dsi234918wms.0.2024.04.05.07.30.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Apr 2024 07:30:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of klarasmodin@gmail.com designates 2a00:1450:4864:20::12a as permitted sender) client-ip=2a00:1450:4864:20::12a;
Received: by mail-lf1-x12a.google.com with SMTP id 2adb3069b0e04-516d47ce662so1282922e87.1
        for <kasan-dev@googlegroups.com>; Fri, 05 Apr 2024 07:30:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWarg9RRNbueAYZSbwzGfqver31F6Yt0ld6k9jgsoFehAiqTCla5O/Tas3GVRInbdU7/8oCcRDbmMAcIu9SqZoEHVjllRgw5LnOjw==
X-Received: by 2002:ac2:454b:0:b0:516:ce0f:738e with SMTP id j11-20020ac2454b000000b00516ce0f738emr1466474lfm.19.1712327422562;
        Fri, 05 Apr 2024 07:30:22 -0700 (PDT)
Received: from ?IPV6:2001:678:a5c:1202:2659:d6e4:5d55:b864? (soda.int.kasm.eu. [2001:678:a5c:1202:2659:d6e4:5d55:b864])
        by smtp.gmail.com with ESMTPSA id 23-20020ac24837000000b00516be080873sm207196lft.8.2024.04.05.07.30.19
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Apr 2024 07:30:22 -0700 (PDT)
Message-ID: <41328d5a-3e41-4936-bcb7-c0a85e6ce332@gmail.com>
Date: Fri, 5 Apr 2024 16:30:19 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v6 00/37] Memory allocation profiling
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
 vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
 mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
 liam.howlett@oracle.com, penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net,
 void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
 catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de,
 mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org,
 peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
 masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
 jhubbard@nvidia.com, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
 paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com,
 yuzhao@google.com, dhowells@redhat.com, hughd@google.com,
 andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com,
 vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
 ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
 rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
 vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, songmuchun@bytedance.com,
 jbaron@akamai.com, aliceryhl@google.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
References: <20240321163705.3067592-1-surenb@google.com>
 <c14cd89b-c879-4474-a800-d60fc29c1820@gmail.com>
 <CAJuCfpHEt2n6sA7m5zvc-F+z=3-twVEKfVGCa0+y62bT10b0Bw@mail.gmail.com>
Content-Language: en-US, sv-SE
From: Klara Modin <klarasmodin@gmail.com>
In-Reply-To: <CAJuCfpHEt2n6sA7m5zvc-F+z=3-twVEKfVGCa0+y62bT10b0Bw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: klarasmodin@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Xz7lRArN;       spf=pass
 (google.com: domain of klarasmodin@gmail.com designates 2a00:1450:4864:20::12a
 as permitted sender) smtp.mailfrom=klarasmodin@gmail.com;       dmarc=pass
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

On 2024-04-05 16:14, Suren Baghdasaryan wrote:
> On Fri, Apr 5, 2024 at 6:37=E2=80=AFAM Klara Modin <klarasmodin@gmail.com=
> wrote:
>> If I enable this, I consistently get percpu allocation failures. I can
>> occasionally reproduce it in qemu. I've attached the logs and my config,
>> please let me know if there's anything else that could be relevant.
>=20
> Thanks for the report!
> In debug_alloc_profiling.log I see:
>=20
> [    7.445127] percpu: limit reached, disable warning
>=20
> That's probably the reason. I'll take a closer look at the cause of
> that and how we can fix it.

Thanks!

>=20
>   In qemu-alloc3.log I see couple of warnings:
>=20
> [    1.111620] alloc_tag was not set
> [    1.111880] WARNING: CPU: 0 PID: 164 at
> include/linux/alloc_tag.h:118 kfree (./include/linux/alloc_tag.h:118
> (discriminator 1) ./include/linux/alloc_tag.h:161 (discriminator 1)
> mm/slub.c:2043 ...
>=20
> [    1.161710] alloc_tag was not cleared (got tag for fs/squashfs/cache.c=
:413)
> [    1.162289] WARNING: CPU: 0 PID: 195 at
> include/linux/alloc_tag.h:109 kmalloc_trace_noprof
> (./include/linux/alloc_tag.h:109 (discriminator 1)
> ./include/linux/alloc_tag.h:149 (discriminator 1) ...
>=20
> Which means we missed to instrument some allocation. Can you please
> check if disabling CONFIG_MEM_ALLOC_PROFILING_DEBUG fixes QEMU case?
> In the meantime I'll try to reproduce and fix this.
> Thanks,
> Suren.

That does seem to be the case from what I can tell. I didn't get the=20
warning in qemu consistently, but it hasn't reappeared for a number of=20
times at least with the debugging option off.

Regards,
Klara Modin

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/41328d5a-3e41-4936-bcb7-c0a85e6ce332%40gmail.com.
