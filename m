Return-Path: <kasan-dev+bncBC32535MUICBBKPTV6XAMGQEYHTVCII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 093C8853FFA
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 00:22:20 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-6e0d8cbfbe3sf2579113b3a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 15:22:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707866538; cv=pass;
        d=google.com; s=arc-20160816;
        b=DzvVndDz0EALI2budpZWM5vluorfsORdPaguMHTYwsOVSRrnpIcpzPn8S/qdPn33Fc
         HQF1nVdAppnZZZwQK2jgVuenjPWP08VRmNWfS626uzj9Vg1hVxHxBvL+LAC+/ropg2JK
         3jK620AMaOqmfhN6UL7LNP8gnLof5ofNGESeCErjZkagJUdOTzaVAFrqPySLDyjCVOCx
         xBchFDmHwo1zD7IUVXprO/H6ALo7qIn1j7b/AHQBM1xwCxXQhfYxCBSHRirxc5kRZTlw
         trIZ8ypMv/B0lkbs+PkKl9xWys4RaR8b3Cy0FRIZVgbdkhPqO9gzV+lfkVgVT0Nqv+Fw
         N1Ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=PMHn+UjjtmmrAKqztfxRj/wteg7ClrR2Q40Ca5TGq3A=;
        fh=9B3ZS0K11qnF2naoHmAP28R33KpowJnl9tLFdnC+OZA=;
        b=WFy/nIGGsIqkH+sRXaWzyXI66Vm3T3or/pdXgVLknFDI/Fx+3PIF8x7ToTUsaJbwmq
         9HYN5yO7JwNbtZ/tTt93KWODEfq7eMzqUVp3XbGcTRQSYR9K+arfU0O7VpcLec+vXeD3
         cJwgPusjofsjJHSeEBAOivYTF53AziAgzVyB+mqt6xvElBYjs6OHho1rMyFESxES3tay
         pHX7MWp5nu5pnJzT/7AlcUiq6nd1k5rdweZyWVZXZq4GaxaKc00eatruT0vPbvbt1gQS
         MV/FEGMY8ZNzKLYiH2oL3rxu/u6OXpMkCwqbxUtzQlQiwIBrp4I9FMPSsEkhKhsXdFHg
         Dwbw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=WIMjLrik;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707866538; x=1708471338; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:organization:autocrypt:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=PMHn+UjjtmmrAKqztfxRj/wteg7ClrR2Q40Ca5TGq3A=;
        b=wQPiieeui3ygJNVMGM5x7SyFgD4GfPh13X59V2gYsHDrI+F8z0CnuAvp70K6GPTO2B
         7W+VDZVwijsBo2/ZBcTZb+j2FtkpT7FsCwgS2VSf5gphBWH2i+XTD56VHbAwXMWTNPcE
         AyIbe8hRmCEScvLdV1Xz7lTgUyHw+GTbkfcFkQar2o4JIjXMGstLhE3YhbTX/A7eSLTk
         Y0P9+aizAv70xuB+KLcmI4BuKKmVkRXDdj0vilRn8R0r0vzZItKoLob5fF/0LxVrquO6
         dW3kYidt1lKZefW/s17ziuucayRD1euLcGTcrImHQLBXeeJjpZMo8fxHUDlepmUnOsmb
         eD4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707866538; x=1708471338;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PMHn+UjjtmmrAKqztfxRj/wteg7ClrR2Q40Ca5TGq3A=;
        b=qvfjAiWakCtTCNBqAIQs0487+RqxBjjf79fkDc7wY8MxfPpqGvNcHe3PqnojRhcVgy
         FJ9frLavPdGk09tUm+currHX7iz0qu2CqMYVjyLuXYlnFfwdiAXqJUHnV+QDBBRujyTA
         u66VrgAmsylPOTdRR/abhqVBedcjXSlSETIJVMEQiNqUgOcbhT263Br56VYAgHKx/pYF
         2AWylTrPiO5GFLkRZ5Lk1TiL78CTSxkKboGLEmGpW0VVF2JywrEoiGYX1k540YyzJ7EH
         +4eMbSIgwnRMzf1n1IuiOOkAvCqBcA23SRnzbOn4EUpPNAvdVidww7YIedYqBOFXFdhR
         z7Pw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXMtCuqTzi7d6GGeUNhF5ARMjHDUXpYqHzSsCEeWqtqmr3yL/aNynq+yIUMGYJcozAwtzH/tAhHsDPTNo26N2ZFP5q6VAQhYw==
X-Gm-Message-State: AOJu0Yy85jWQ0CS8t4B2ivIPYK0+kPsuE6C0GakFgwWS8IgyJP7Fr8pv
	6DSJdw95J0IPsnSDHwjBth0VpdNEswt+Os1uqevTaSF8nLm9wNtA
X-Google-Smtp-Source: AGHT+IE9+cyUX6GhwrQb+JIO+gXba9AZ8mrdJFWp6gRj9uIqEwaaz4AIxI06IOpfTxc738261Qwc8A==
X-Received: by 2002:a05:6a00:1988:b0:6db:624e:93cd with SMTP id d8-20020a056a00198800b006db624e93cdmr811862pfl.23.1707866537848;
        Tue, 13 Feb 2024 15:22:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1d03:b0:6e0:e4d2:d340 with SMTP id
 a3-20020a056a001d0300b006e0e4d2d340ls1286479pfx.2.-pod-prod-07-us; Tue, 13
 Feb 2024 15:22:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV1uAX8dCswUi4HK2+jXIe9PWxQoWWzB1z8fFkibYF4wgpwiz3fJ0NPpNkm8qQb7khMvkKRcXxosm2Z9nNpHkGHfEZuZIs7tDGEBg==
X-Received: by 2002:a05:6a00:1b44:b0:6e0:3827:4d23 with SMTP id o4-20020a056a001b4400b006e038274d23mr682397pfv.15.1707866536518;
        Tue, 13 Feb 2024 15:22:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707866536; cv=none;
        d=google.com; s=arc-20160816;
        b=R11i2XfRGoWNG3bQKcBeAUKrNaB3Jow7I7wjhov421HNjPG4WsWOxbUyJn4ISqvwIz
         ITC0LEAieQ7z70ml7zcyoE9tM+Rq5aRiM3DSB3pIe0LVC2Ez62Gf0elXcIGSBZN6SH8e
         bdNfNGlFpjv/RnWSqBGgGjF5BrlGqGa1u3UbUW9S0S6o191N2W9zSRKw4NVn9FYFhKJS
         53Ijm91ESFFccIEWFeeczem7pZQrDTjPrHgiusSYkesosRDgR+j5mHSs7pcYg+y2YKmI
         +gEK9FYDddy10HblQ3fECeEgUjJLn1pRt0Uznum5TgX/UHzn2PxU643r8lBSlqtrTyOs
         Z2qQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=cZAfitLnBMjrYyoOukrJIwYyfYo9MO8Q5HzfCPeVj3g=;
        fh=3CQmBs+W2r+hy155laicJ2P52MEJgUfiKG9dcbPyOXQ=;
        b=yAgrZyp9KjjJAV2aTAwIR21fo5iNTRtMLIn4MDI6s1umSRlbF+pyOgKGEpAtCGbFP7
         1T99D/5Ei+nXQVisyqg7tWJkni7rpCQkYzJuaTO6hOnWVBdT0LUWfAgalazu7uxx0g9H
         P5NKHYAjymmtqSd2GpemfW5FOOefvdHDdkSbZJ+VW3OwSIch3Cjncre1EDOySRSu6ILi
         bFkWZtZm8ynfhDqgjCbgM/it06EBuLPXhDok7EupB7tf6xhFzvWwuu5ixEoqkeBvav5t
         +DdMTppoypId6+KjedY6fxLl/W9KqCDxJEILZhZhE1n2S+yNaGmI8i8bpudtC8LMchSF
         vLcA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=WIMjLrik;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
X-Forwarded-Encrypted: i=1; AJvYcCV192Q2IndpV1edZb27jyY1B6C1bOQg6LSOfXJzkiOziCmtXmZL7EJhI6BZURYjEd4+cXykeXUUj8PnMvYXH4EqerrgGh6xTDPFGA==
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id n63-20020a632742000000b005dc2e3165adsi422073pgn.3.2024.02.13.15.22.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Feb 2024 15:22:16 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com
 [209.85.128.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-331-uKsf98JyOOaueU_7Bq-APQ-1; Tue, 13 Feb 2024 18:22:14 -0500
X-MC-Unique: uKsf98JyOOaueU_7Bq-APQ-1
Received: by mail-wm1-f69.google.com with SMTP id 5b1f17b1804b1-40e53200380so30138185e9.3
        for <kasan-dev@googlegroups.com>; Tue, 13 Feb 2024 15:22:14 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVp5DSAfLpGGbRZN/tBmZ+SZxNzN1Pxqv0eiXeMTTFHrh4Iwe1R6Dvznd//Ju2ry3mViWu3/iET9H0x3ub/AAyhL9kOM3tfAmleXQ==
X-Received: by 2002:a05:600c:4f0e:b0:410:df8f:9ffa with SMTP id l14-20020a05600c4f0e00b00410df8f9ffamr700151wmq.25.1707866533002;
        Tue, 13 Feb 2024 15:22:13 -0800 (PST)
X-Received: by 2002:a05:600c:4f0e:b0:410:df8f:9ffa with SMTP id l14-20020a05600c4f0e00b00410df8f9ffamr700105wmq.25.1707866532537;
        Tue, 13 Feb 2024 15:22:12 -0800 (PST)
X-Forwarded-Encrypted: i=1; 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
Received: from ?IPV6:2003:d8:2f3c:3f00:7177:eb0c:d3d2:4b0e? (p200300d82f3c3f007177eb0cd3d24b0e.dip0.t-ipconnect.de. [2003:d8:2f3c:3f00:7177:eb0c:d3d2:4b0e])
        by smtp.gmail.com with ESMTPSA id t17-20020a05600c451100b0040fdf5e6d40sm158264wmo.20.2024.02.13.15.22.09
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Feb 2024 15:22:11 -0800 (PST)
Message-ID: <c842347d-5794-4925-9b95-e9966795b7e1@redhat.com>
Date: Wed, 14 Feb 2024 00:22:08 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>,
 akpm@linux-foundation.org, vbabka@suse.cz, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
 void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
 catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de,
 mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org,
 peterx@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org,
 ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
 bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
References: <Zctfa2DvmlTYSfe8@tiehlicka>
 <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
 <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com>
 <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
 <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com>
 <CAJuCfpEtOhzL65eMDk2W5SchcquN9hMCcbfD50a-FgtPgxh4Fw@mail.gmail.com>
 <adbb77ee-1662-4d24-bcbf-d74c29bc5083@redhat.com>
 <r6cmbcmalryodbnlkmuj2fjnausbcysmolikjguqvdwkngeztq@45lbvxjavwb3>
 <CAJuCfpF4g1jeEwHVHjQWwi5kqS-3UqjMt7GnG0Kdz5VJGyhK3Q@mail.gmail.com>
 <a9b0440b-844e-4e45-a546-315d53322aad@redhat.com>
 <xbehqbtjp5wi4z2ppzrbmlj6vfazd2w5flz3tgjbo37tlisexa@caq633gciggt>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <xbehqbtjp5wi4z2ppzrbmlj6vfazd2w5flz3tgjbo37tlisexa@caq633gciggt>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=WIMjLrik;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 14.02.24 00:12, Kent Overstreet wrote:
> On Wed, Feb 14, 2024 at 12:02:30AM +0100, David Hildenbrand wrote:
>> On 13.02.24 23:59, Suren Baghdasaryan wrote:
>>> On Tue, Feb 13, 2024 at 2:50=E2=80=AFPM Kent Overstreet
>>> <kent.overstreet@linux.dev> wrote:
>>>>
>>>> On Tue, Feb 13, 2024 at 11:48:41PM +0100, David Hildenbrand wrote:
>>>>> On 13.02.24 23:30, Suren Baghdasaryan wrote:
>>>>>> On Tue, Feb 13, 2024 at 2:17=E2=80=AFPM David Hildenbrand <david@red=
hat.com> wrote:
>>>>>>>
>>>>>>> On 13.02.24 23:09, Kent Overstreet wrote:
>>>>>>>> On Tue, Feb 13, 2024 at 11:04:58PM +0100, David Hildenbrand wrote:
>>>>>>>>> On 13.02.24 22:58, Suren Baghdasaryan wrote:
>>>>>>>>>> On Tue, Feb 13, 2024 at 4:24=E2=80=AFAM Michal Hocko <mhocko@sus=
e.com> wrote:
>>>>>>>>>>>
>>>>>>>>>>> On Mon 12-02-24 13:38:46, Suren Baghdasaryan wrote:
>>>>>>>>>>> [...]
>>>>>>>>>>>> We're aiming to get this in the next merge window, for 6.9. Th=
e feedback
>>>>>>>>>>>> we've gotten has been that even out of tree this patchset has =
already
>>>>>>>>>>>> been useful, and there's a significant amount of other work ga=
ted on the
>>>>>>>>>>>> code tagging functionality included in this patchset [2].
>>>>>>>>>>>
>>>>>>>>>>> I suspect it will not come as a surprise that I really dislike =
the
>>>>>>>>>>> implementation proposed here. I will not repeat my arguments, I=
 have
>>>>>>>>>>> done so on several occasions already.
>>>>>>>>>>>
>>>>>>>>>>> Anyway, I didn't go as far as to nak it even though I _strongly=
_ believe
>>>>>>>>>>> this debugging feature will add a maintenance overhead for a ve=
ry long
>>>>>>>>>>> time. I can live with all the downsides of the proposed impleme=
ntation
>>>>>>>>>>> _as long as_ there is a wider agreement from the MM community a=
s this is
>>>>>>>>>>> where the maintenance cost will be payed. So far I have not see=
n (m)any
>>>>>>>>>>> acks by MM developers so aiming into the next merge window is m=
ore than
>>>>>>>>>>> little rushed.
>>>>>>>>>>
>>>>>>>>>> We tried other previously proposed approaches and all have their
>>>>>>>>>> downsides without making maintenance much easier. Your position =
is
>>>>>>>>>> understandable and I think it's fair. Let's see if others see mo=
re
>>>>>>>>>> benefit than cost here.
>>>>>>>>>
>>>>>>>>> Would it make sense to discuss that at LSF/MM once again, especia=
lly
>>>>>>>>> covering why proposed alternatives did not work out? LSF/MM is no=
t "too far"
>>>>>>>>> away (May).
>>>>>>>>>
>>>>>>>>> I recall that the last LSF/MM session on this topic was a bit unf=
ortunate
>>>>>>>>> (IMHO not as productive as it could have been). Maybe we can fina=
lly reach a
>>>>>>>>> consensus on this.
>>>>>>>>
>>>>>>>> I'd rather not delay for more bikeshedding. Before agreeing to LSF=
 I'd
>>>>>>>> need to see a serious proposl - what we had at the last LSF was pe=
ople
>>>>>>>> jumping in with half baked alternative proposals that very much ha=
dn't
>>>>>>>> been thought through, and I see no need to repeat that.
>>>>>>>>
>>>>>>>> Like I mentioned, there's other work gated on this patchset; if pe=
ople
>>>>>>>> want to hold this up for more discussion they better be putting fo=
rth
>>>>>>>> something to discuss.
>>>>>>>
>>>>>>> I'm thinking of ways on how to achieve Michal's request: "as long a=
s
>>>>>>> there is a wider agreement from the MM community". If we can achiev=
e
>>>>>>> that without LSF, great! (a bi-weekly MM meeting might also be an o=
ption)
>>>>>>
>>>>>> There will be a maintenance burden even with the cleanest proposed
>>>>>> approach.
>>>>>
>>>>> Yes.
>>>>>
>>>>>> We worked hard to make the patchset as clean as possible and
>>>>>> if benefits still don't outweigh the maintenance cost then we should
>>>>>> probably stop trying.
>>>>>
>>>>> Indeed.
>>>>>
>>>>>> At LSF/MM I would rather discuss functonal
>>>>>> issues/requirements/improvements than alternative approaches to
>>>>>> instrument allocators.
>>>>>> I'm happy to arrange a separate meeting with MM folks if that would
>>>>>> help to progress on the cost/benefit decision.
>>>>> Note that I am only proposing ways forward.
>>>>>
>>>>> If you think you can easily achieve what Michal requested without all=
 that,
>>>>> good.
>>>>
>>>> He requested something?
>>>
>>> Yes, a cleaner instrumentation. Unfortunately the cleanest one is not
>>> possible until the compiler feature is developed and deployed. And it
>>> still would require changes to the headers, so don't think it's worth
>>> delaying the feature for years.
>>>
>>
>> I was talking about this: "I can live with all the downsides of the prop=
osed
>> implementationas long as there is a wider agreement from the MM communit=
y as
>> this is where the maintenance cost will be payed. So far I have not seen
>> (m)any acks by MM developers".
>>
>> I certainly cannot be motivated at this point to review and ack this,
>> unfortunately too much negative energy around here.
>=20
> David, this kind of reaction is exactly why I was telling Andrew I was
> going to submit this as a direct pull request to Linus.
>=20
> This is an important feature; if we can't stay focused ot the technical
> and get it done that's what I'll do.

Kent, I started this with "Would it make sense" in an attempt to help=20
Suren and you to finally make progress with this, one way or the other.=20
I know that there were ways in the past to get the MM community to agree=20
on such things.

I tried to be helpful, finding ways *not having to* bypass the MM=20
community to get MM stuff merged.

The reply I got is mostly negative energy.

So you don't need my help here, understood.

But I will fight against any attempts to bypass the MM community.

--=20
Cheers,

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/c842347d-5794-4925-9b95-e9966795b7e1%40redhat.com.
