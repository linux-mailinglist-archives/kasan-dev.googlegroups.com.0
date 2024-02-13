Return-Path: <kasan-dev+bncBC32535MUICBBE6PV6XAMGQEH7QXVBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 01F9D853E05
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 23:05:09 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-68c7947e07dsf53531046d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 14:05:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707861907; cv=pass;
        d=google.com; s=arc-20160816;
        b=wpK5b7QlKINKjlaa93C3nkNMAdqgmK39VjLx6xIp1pqbJ8+7iPzySh3EtHVbCdzl83
         UM/K1sRTv0Ob3AgqelqMRKlm/qxgbwp3DO/6HwRS8ZwrpUjhmlaGWgYOYcRvd7UEb1Ic
         1tseK+K47kda1TOAmUCBM/UlAl0GPJB2JbDkk+01/iZvMike40oFiRjRn4KTBDCDCP6u
         3omVICUcccxB0KMNkc9DzcRtiSNTQ9PFWLunDy8yNBZXmlOZq2XYy34njoMwhILF8HLH
         zlSNwxXm2C9WAYsjnDviIuQKtAoVlR+MmPsVn67VgrMLqpyud0yp5JyNC8qlAx8BrLZr
         30dA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=Db9m8ODpFiaRDwpC1LUs9dLcaIXk/OaIwPsd04YbrCE=;
        fh=1j39ERuBZCZfsS0YlTLBc1VMHHDIGQ4Ir9g/41lhMzo=;
        b=HXQIn/0pVDwu4Tykq0nr2t8WZapZk+p6rV5ykNfvYU7e4JAIeRfrzpigq70tfCCzfP
         PdVBD1XHb/cSIeobt6zsyM6RNGl28Yi3ZkzMqfQM0Pqn9PZEbA/vCuzeT8vIF09wrR1G
         9Q0wDdUWsrOb0QG20Mh/qW2lmqc3IJV1/llD/1FNnhye5zUNeqXM1TfykBwy4ZElPo3R
         kcM+iyNu4WB/GwuJy3yxW4TNqtY3gwU//llg4B9Ya15VawdCH/EYKtaaWpztOezr5ZUP
         O80FqHRuicIs9jjJTxTqEUcZeK//UkFw/RFtR4cFnSvDj6nm2WCxdyqJzLX01DM+thMB
         K1yA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dg9iVx++;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707861907; x=1708466707; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:organization:autocrypt:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Db9m8ODpFiaRDwpC1LUs9dLcaIXk/OaIwPsd04YbrCE=;
        b=DrRJqh7vc9abNqshZupSLlAWBesDS3l1Wzw23iDsH1OA56yPp2NPXCoiIsswVbgpsl
         LcyczUNng7SDvOVQ7WANalf/JEK6fZ/qIXMNaVV/aBEKVv6ar9kIKbaZiJlsl3B0z8l8
         Xlfr7z4T9+Q+GA7wN0oyQWzJMO6pHOdOnrwwMVEIPRBgFWiXlMA4bFWDVlLwEUFozf+T
         2POYKxUt1IuKUvwab6WFXwfwE9hnI897W+YgM1F5fGnXJyZi0RGaNwNpCisZzORRrCWh
         zlJ78wN6zbOqnCCF+dZMhfUU914GBh7wf4LIshux9SEr+l69g6QQZU4TNUpWk3OwNrC5
         opYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707861907; x=1708466707;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Db9m8ODpFiaRDwpC1LUs9dLcaIXk/OaIwPsd04YbrCE=;
        b=xHGy8/pymlcTCSlD4iZYfZohOYU2kRF2i6bzn6XdsIC42XxRMWI+ZFGiZ5rhzkqK3I
         /MIaHv+PL+D6up4HKbiDEoeDPaeuFRjdpIrFjW+/zADrbEfbnC8fZQOsoKV4LVs0BHXG
         /r9mm8MZKxHUABZjBGk7uwWCdJgB3IN1677zn4gh4fUQmVgJw1t/CiQRXhHDCnDTHQ6J
         FCFqLnsljiEg+WhJ24BH1OXn8BlvCCxqsRj5ozsfRhhj8lcnebYZlg8H10se77P00/qC
         l4H7/YGx2sWrrrsVt0wOhBpG8P1Z1Ft+NUXp4MlFwsAkZMTuMpnNaGNLl7hABbWbrHe2
         QZTw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUBrtHHRBZsKYUmO4xnlO5q86GzXVrMlbDU7yIvL29eQz02eNPXeLdTXAjAsmVMpORGLKqIqt9k3GfMSl1RTwdMnpo27sR/ZA==
X-Gm-Message-State: AOJu0YxdO5eVOBXRiAMCqswe0jUVIwRxCT7+DCBR4PxJwOrFEas0XG6w
	kJe7JF77GfcBxSifO+ZoAdDuvhrihuh3x3yifBm/ViVKSdnNcsF2
X-Google-Smtp-Source: AGHT+IET+z30Mb+U+KN6dsg/664WCw/d0eKr5ywbUYHWKBySHOsTBembqHfX9CC2AW4KWKQeOdb2yA==
X-Received: by 2002:a05:6214:40f:b0:68c:aa6f:b54e with SMTP id z15-20020a056214040f00b0068caa6fb54emr798089qvx.58.1707861907546;
        Tue, 13 Feb 2024 14:05:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5c6f:0:b0:67f:4e7a:d81e with SMTP id i15-20020ad45c6f000000b0067f4e7ad81els7229189qvh.2.-pod-prod-03-us;
 Tue, 13 Feb 2024 14:05:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWASKpv1bPJZlqkBt3Kya1A1+UExU9iQyXoxCvOwZU5lrSf8fZ7XA3/08G/CPAS+GAAhLKy5m9PA5fisZqPhDYIqyYazLAyk+p9wA==
X-Received: by 2002:a05:6102:50a5:b0:46d:5c95:cca2 with SMTP id bl37-20020a05610250a500b0046d5c95cca2mr1052378vsb.4.1707861906064;
        Tue, 13 Feb 2024 14:05:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707861906; cv=none;
        d=google.com; s=arc-20160816;
        b=CA8YvQbU8c68d1JpgY2bpTUuUAKCyx7Os5BSF7UIrrrucNxcjfohd56f+vGpk2B37V
         EPngjhcqsPAj5I/fCbBaVt8XzEhblJM1ZoVfNDcSFvUfqDZbSgqZPw/1Om8IAOV/X95a
         CceEEcLblHfmkM1pwrz1LvhrIhDIeVOtYn3ht0PDoKeQN9EkLjkoENi+553Htkljk8F9
         7ZaQR3pdQbLTPs9q7qBSgLH7qhovYjXM2nhLyHUjbQo6aS6bMwRX5s3zRzQjBTYi1yyj
         QV+mLtbVXNCJ0Yfui0ZaRkCnsjbrXUZNgEHjOSXDkLnbP9SNw3lHE89Nda2JsZVHaDpH
         KmpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=RgZc24jjJQqeC7+KfoYWO0hi8grRBBzECQH5kw6TD04=;
        fh=D1jx+U8+eQ0+ewIyrUY6dZLdoFWjQpSBxaJYHQCHz3s=;
        b=vwzmOFlsoUm2YfUhTT430emIKbBhQds4oUHoJG5zXR7vuw06YFwWomqMOQo151e51N
         b0jmNtrV4rlbV20zOPfhutpnq1lsZrpkF6GrIQsd3Mfw5ARPGpQTP2b6C7+HlW+gQi0U
         PfCvF/JdioBYLxljN1rsy7q5W0eDDRJTOJX8ObEmj1DljCBMjZlbKMKfORFaZRvR2ySO
         4fVSuCZSXBM+rXK9+XuDmnkv7AJilJ5NXgLPPM50Jvssu8z9S44M386YnLMZ9p1r/jOV
         EZc6YtejC3d2XoY8dycB/ShDhmt7smPKcz4adIxfHdq7Npb6jwhSngYGc2RmdxOcb2ZB
         6aYg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dg9iVx++;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
X-Forwarded-Encrypted: i=1; AJvYcCVFINhmJ6ZMS/fyaiD39cxbKZGhHQ3i0P0fPsf1O1g9H2jgLUqGDG8z3wvuJ89q9cNV3X3n2V76GUrXCjKrJc6U3mVu12dWFReWDQ==
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id h24-20020a67c598000000b0046d3d08309esi822065vsk.1.2024.02.13.14.05.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Feb 2024 14:05:05 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com
 [209.85.128.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-70-SlSQSPbkP5CUgHscw0jMpA-1; Tue, 13 Feb 2024 17:05:03 -0500
X-MC-Unique: SlSQSPbkP5CUgHscw0jMpA-1
Received: by mail-wm1-f69.google.com with SMTP id 5b1f17b1804b1-411e24b69f7so465995e9.3
        for <kasan-dev@googlegroups.com>; Tue, 13 Feb 2024 14:05:03 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXYx2BkEFGNZ5Tv9CT/UigVlxSCfUHNKghKFIs0+j/ESgg85M+N4N39Pp/lAewMrma7S6TdmpkWPOSPDcfOAa2u+2Ot8sAesZaw7g==
X-Received: by 2002:a05:600c:45ca:b0:40e:bfbf:f368 with SMTP id s10-20020a05600c45ca00b0040ebfbff368mr650492wmo.2.1707861902190;
        Tue, 13 Feb 2024 14:05:02 -0800 (PST)
X-Received: by 2002:a05:600c:45ca:b0:40e:bfbf:f368 with SMTP id s10-20020a05600c45ca00b0040ebfbff368mr650468wmo.2.1707861901793;
        Tue, 13 Feb 2024 14:05:01 -0800 (PST)
X-Forwarded-Encrypted: i=1; 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
Received: from ?IPV6:2003:d8:2f3c:3f00:7177:eb0c:d3d2:4b0e? (p200300d82f3c3f007177eb0cd3d24b0e.dip0.t-ipconnect.de. [2003:d8:2f3c:3f00:7177:eb0c:d3d2:4b0e])
        by smtp.gmail.com with ESMTPSA id jh2-20020a05600ca08200b00410e6a6403esm17251wmb.34.2024.02.13.14.04.58
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Feb 2024 14:05:01 -0800 (PST)
Message-ID: <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com>
Date: Tue, 13 Feb 2024 23:04:58 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
To: Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, vbabka@suse.cz,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 corbet@lwn.net, void@manifault.com, peterz@infradead.org,
 juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
 arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org,
 dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
 paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com,
 yuzhao@google.com, dhowells@redhat.com, hughd@google.com,
 andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com,
 vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
 ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
 rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
 vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
References: <20240212213922.783301-1-surenb@google.com>
 <Zctfa2DvmlTYSfe8@tiehlicka>
 <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=dg9iVx++;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

On 13.02.24 22:58, Suren Baghdasaryan wrote:
> On Tue, Feb 13, 2024 at 4:24=E2=80=AFAM Michal Hocko <mhocko@suse.com> wr=
ote:
>>
>> On Mon 12-02-24 13:38:46, Suren Baghdasaryan wrote:
>> [...]
>>> We're aiming to get this in the next merge window, for 6.9. The feedbac=
k
>>> we've gotten has been that even out of tree this patchset has already
>>> been useful, and there's a significant amount of other work gated on th=
e
>>> code tagging functionality included in this patchset [2].
>>
>> I suspect it will not come as a surprise that I really dislike the
>> implementation proposed here. I will not repeat my arguments, I have
>> done so on several occasions already.
>>
>> Anyway, I didn't go as far as to nak it even though I _strongly_ believe
>> this debugging feature will add a maintenance overhead for a very long
>> time. I can live with all the downsides of the proposed implementation
>> _as long as_ there is a wider agreement from the MM community as this is
>> where the maintenance cost will be payed. So far I have not seen (m)any
>> acks by MM developers so aiming into the next merge window is more than
>> little rushed.
>=20
> We tried other previously proposed approaches and all have their
> downsides without making maintenance much easier. Your position is
> understandable and I think it's fair. Let's see if others see more
> benefit than cost here.

Would it make sense to discuss that at LSF/MM once again, especially=20
covering why proposed alternatives did not work out? LSF/MM is not "too=20
far" away (May).

I recall that the last LSF/MM session on this topic was a bit=20
unfortunate (IMHO not as productive as it could have been). Maybe we can=20
finally reach a consensus on this.

--=20
Cheers,

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/9e14adec-2842-458d-8a58-af6a2d18d823%40redhat.com.
