Return-Path: <kasan-dev+bncBC32535MUICBBUXDV6XAMGQEEWFTMVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C133853F16
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 23:48:52 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-59d77bac3besf1442647eaf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 14:48:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707864531; cv=pass;
        d=google.com; s=arc-20160816;
        b=f0c/hyIuxLAwTh1ngwQ52pPIgqH7bTehZD87gZNjriRLRdEyamGIQVP69foS7QWILJ
         KjsetHBjE85DazQyK5dTji4OgnWEdS9BkMhl/jVrDzcLD0BqS8e+H2X1mQLIaivvD8IP
         PUGCibW+dlGzsKFF7/7XXjbpakLuoXh+VjmKdxNNtyVBODH7y48MhopNBtOdYNnqDMBr
         odfhTQodjUkXKfF2OWzG4erERI8uCfDa94wuvx1OAvyfs85i+V+1kvb6vN/3YOMWlI8+
         U7R/2zi/J0LZV/QP28IzRyIdXEQ2ToIkykLmQTDrgnwiaG7qVElgI3P8OV6P7v4RYPhB
         PApA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=NHTvyj53ImRqAIDayl6xRLBJYxzrx+7t5UA/b9Oa4rg=;
        fh=+IHrM7ZDx09t6TL9Hh7ZCU3aoYrlh1QzJkvPzlgdR6s=;
        b=xwoOKZqkN2nHM9QnQ2dARl867KPTB59fMeLqLpA38bnn+9JILKDqSWfOQOn0yFP7ho
         XPEpGxs1hy/04a9WvicCm7CUc99XmNS7VGBm7SqR7yX8eyIuG1B9UJKX2Vu9xL5sKUUh
         ht9DA68azIxpgmvLYk1XGKTQGfNnOCcFItKnYrUVEHl3WfS6VDPribOGSrNJYpfIhMuV
         AlT5LM+NwAFLxm7yTNGNLztPujZcNW1uN3sI9mEY+FS3lXwzGjcxcVzWMrU//bNbrwzb
         oJc7NDhO/IObtAuJScj5td4hjzuZxwsPw4g1/LbknHU+P8/R4zquaJVeZGf9WU9yPgev
         T8qA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=P9vSGo0h;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707864531; x=1708469331; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:organization:autocrypt:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=NHTvyj53ImRqAIDayl6xRLBJYxzrx+7t5UA/b9Oa4rg=;
        b=sHbqPi/X6WmwKhGnjrSG7h3ouZi/QdQ3ir2uUNLiPO/BemwyVyEV629YqTuPbXw8Uo
         GumaI1XQ+3cN+1GVs5j1CH+bKT82KDszXqj0h+Owv9CI3KyRSf+XQiIOX/nPjQshukbp
         PzNCfwWNRWTCJwZKTRt+x+sRwKF37CGUp8+YQmIltL52mNMeFaBNaigVi6Sdpc0oFCYa
         LUwJ8lBEYv7crERNZvtVPrAJR3QrpWk3yHIVwzqxwf1RCbqYOpRsIqGW+nQ12SticDoo
         8yU9vh0I0c37Lnco5OIETUiBFAntqdz5zggCoCbtB9m0OlZut3KhMdoz4cxmYsNnGOBz
         rFDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707864531; x=1708469331;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NHTvyj53ImRqAIDayl6xRLBJYxzrx+7t5UA/b9Oa4rg=;
        b=LPJGrHg5xEEZOelsIH5xb+GIxuaOcb6eMJ++e0Gl1psrwx5Lcpt2pOOxTpoHT5iJVG
         wbua1kFscwSpBNJR7kUjlA6d43ao2/5dx/m5q3r1fhwDLT70xsqEWJFPE/GfheYwuPVP
         WKyqfwxXnvO2Zer2kuZV2oSO1Xzbw2pxGy+CMQJDtcageDUmQAoNj7ZXz7qN5ahwgDhh
         R/momeq33xsil5OuLSGLd/wxiEOlEz4MOZvmkJ/abEBLQFjj597rooVOVVHWkJbYLlZ/
         u4MPbqd1sJ2ti5UJmjXjOOwM8zn/3t5PgsfePGFg9dtXY8PxrzSWViiCxV2fSltAuI5x
         UWXQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWL4sKoIKnujrmidGEPc3ajJGxaLTzWp2vgKUCDvdFOgDej4/Fk04dFdSTIyDxo8r5RTuE0mG8f8GnlAMJ9Kap8Ew+adQkjsg==
X-Gm-Message-State: AOJu0Ywv/Ip1bheWOeDitc5+kI48ANqWw9FA3sq/c0vzRH/wNwd2uzgi
	k91jGhL7Tm7q63jTeaWGJRc+kiGTE7iSfi7yV7IKBwb6XhvEvTLj
X-Google-Smtp-Source: AGHT+IFuPjXtmx0KfG8D7wGBLBzg5lCa3LJjh/kacUYzB82pFVLpPJBilh51MMQoAp+yBTiRfnaEJg==
X-Received: by 2002:a05:6820:1b8e:b0:59d:d34f:7eda with SMTP id cb14-20020a0568201b8e00b0059dd34f7edamr1323830oob.0.1707864530729;
        Tue, 13 Feb 2024 14:48:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:ae08:0:b0:59c:8811:7841 with SMTP id z8-20020a4aae08000000b0059c88117841ls710008oom.2.-pod-prod-05-us;
 Tue, 13 Feb 2024 14:48:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVwujqDb2NfHIxYDaqx6D5cGVLL+lMYc7BM+CAYVaUpzldmjJXPqT+6RJlBlF6AnWGYUINXH21cxcTKaRIh8i3q1shU13pJxGrZww==
X-Received: by 2002:a9d:6ac2:0:b0:6e2:dae7:eba3 with SMTP id m2-20020a9d6ac2000000b006e2dae7eba3mr1190209otq.19.1707864529774;
        Tue, 13 Feb 2024 14:48:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707864529; cv=none;
        d=google.com; s=arc-20160816;
        b=Bo7Ubvh8LP0ywIkPKBRmX1w6UyeayKbyqYjDZsnQ4Mg+IQ8CBT9+b1+WfMGhWdugCc
         IEEHW8AN03zUebzbR7PfaxIjikdx0QAz2Knj4weGZ7c8Ny91zv3C41x0RUmnA+tvmqRK
         HV49H1a2yFThNMsLGPbNJTf0NJBpEtTZa0H2kBm3Qc6BRTLIPEwtX4jgbR/ksUZGFyDC
         CdlyMb6s2sLj0t6akuaLK6tqgj+L72SEMlJnQs0ekIbWDepDRdz41xOuUTc1TxmXpLED
         sE0/Vm1u87KPxbXaPoyQY+UnYEh14l720BPVbQ4JmODdaXLZtqyfwolGVoxCRMd3U5wz
         5RCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=fUzYvptXwU+wpVXUT9gyu0he36rKpcH8guCwJL2uHOc=;
        fh=iv1baFYUbDD6ISQ8W+YANTJvtKiGcuya7e0+x9w+qZI=;
        b=MByIUZtWxP49nwiApiFH11ui/nP4XRlCk8m2rakaa6VLLj89SDmac2pmm5yFIceopN
         OLW1hFGS6dZcd9XL4OEQBNUvN/XQofojyRBzFaWT1veIrPKMAhTkO6eNz9ytXPo+UTEi
         s55uYjg2tIPOljqNIcWaYK50AIsQ75sqsVLqWxEzvVTT7WpKjowW0idGfWIizS6ee6hh
         VX0iCu10AckOo12bBlts7IJob7dpWtenCXkAjkRBAixDju7bLnQru2iA3tYaNULmPAAw
         3AojLFbp/A47HRrVjd/FlMcf9JhsYsTQCDqdCNVn8Cu1PXiCbFf6Yyx781olRr0Ob+nw
         xm/g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=P9vSGo0h;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
X-Forwarded-Encrypted: i=1; AJvYcCUCr+++3RcOOVnIJZnJvUt3CDVsVq4ohS8xVyhMnhahvBEH27hSixH9ubJUgT7qZY1CaUn9M6YQpHWRQ9k2pZFPtglisvGLrQ+BFg==
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id cr5-20020a056830670500b006e2e0db4a09si385457otb.3.2024.02.13.14.48.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Feb 2024 14:48:49 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-113-hvlZLwKpPgqO4C4EkxP-ZQ-1; Tue, 13 Feb 2024 17:48:47 -0500
X-MC-Unique: hvlZLwKpPgqO4C4EkxP-ZQ-1
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-410bce883a3so16403305e9.2
        for <kasan-dev@googlegroups.com>; Tue, 13 Feb 2024 14:48:46 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXA0BuIbX+AnGB3KBL/hToWPBFXO6UPtEo29RnyanPrVI8q+X7/M4NKmRhcZfuVuY2GvdkwfbQ/KhzQBZWwq8dNk2mhcgAS7gHoGA==
X-Received: by 2002:a05:6000:1289:b0:33b:4382:c50 with SMTP id f9-20020a056000128900b0033b43820c50mr399569wrx.26.1707864525838;
        Tue, 13 Feb 2024 14:48:45 -0800 (PST)
X-Received: by 2002:a05:6000:1289:b0:33b:4382:c50 with SMTP id f9-20020a056000128900b0033b43820c50mr399523wrx.26.1707864525398;
        Tue, 13 Feb 2024 14:48:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; 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
Received: from ?IPV6:2003:d8:2f3c:3f00:7177:eb0c:d3d2:4b0e? (p200300d82f3c3f007177eb0cd3d24b0e.dip0.t-ipconnect.de. [2003:d8:2f3c:3f00:7177:eb0c:d3d2:4b0e])
        by smtp.gmail.com with ESMTPSA id bv14-20020a0560001f0e00b0033b784c2775sm8751825wrb.43.2024.02.13.14.48.42
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Feb 2024 14:48:44 -0800 (PST)
Message-ID: <adbb77ee-1662-4d24-bcbf-d74c29bc5083@redhat.com>
Date: Tue, 13 Feb 2024 23:48:41 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
To: Suren Baghdasaryan <surenb@google.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
 Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, vbabka@suse.cz,
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
 <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com>
 <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
 <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com>
 <CAJuCfpEtOhzL65eMDk2W5SchcquN9hMCcbfD50a-FgtPgxh4Fw@mail.gmail.com>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <CAJuCfpEtOhzL65eMDk2W5SchcquN9hMCcbfD50a-FgtPgxh4Fw@mail.gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=P9vSGo0h;
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

On 13.02.24 23:30, Suren Baghdasaryan wrote:
> On Tue, Feb 13, 2024 at 2:17=E2=80=AFPM David Hildenbrand <david@redhat.c=
om> wrote:
>>
>> On 13.02.24 23:09, Kent Overstreet wrote:
>>> On Tue, Feb 13, 2024 at 11:04:58PM +0100, David Hildenbrand wrote:
>>>> On 13.02.24 22:58, Suren Baghdasaryan wrote:
>>>>> On Tue, Feb 13, 2024 at 4:24=E2=80=AFAM Michal Hocko <mhocko@suse.com=
> wrote:
>>>>>>
>>>>>> On Mon 12-02-24 13:38:46, Suren Baghdasaryan wrote:
>>>>>> [...]
>>>>>>> We're aiming to get this in the next merge window, for 6.9. The fee=
dback
>>>>>>> we've gotten has been that even out of tree this patchset has alrea=
dy
>>>>>>> been useful, and there's a significant amount of other work gated o=
n the
>>>>>>> code tagging functionality included in this patchset [2].
>>>>>>
>>>>>> I suspect it will not come as a surprise that I really dislike the
>>>>>> implementation proposed here. I will not repeat my arguments, I have
>>>>>> done so on several occasions already.
>>>>>>
>>>>>> Anyway, I didn't go as far as to nak it even though I _strongly_ bel=
ieve
>>>>>> this debugging feature will add a maintenance overhead for a very lo=
ng
>>>>>> time. I can live with all the downsides of the proposed implementati=
on
>>>>>> _as long as_ there is a wider agreement from the MM community as thi=
s is
>>>>>> where the maintenance cost will be payed. So far I have not seen (m)=
any
>>>>>> acks by MM developers so aiming into the next merge window is more t=
han
>>>>>> little rushed.
>>>>>
>>>>> We tried other previously proposed approaches and all have their
>>>>> downsides without making maintenance much easier. Your position is
>>>>> understandable and I think it's fair. Let's see if others see more
>>>>> benefit than cost here.
>>>>
>>>> Would it make sense to discuss that at LSF/MM once again, especially
>>>> covering why proposed alternatives did not work out? LSF/MM is not "to=
o far"
>>>> away (May).
>>>>
>>>> I recall that the last LSF/MM session on this topic was a bit unfortun=
ate
>>>> (IMHO not as productive as it could have been). Maybe we can finally r=
each a
>>>> consensus on this.
>>>
>>> I'd rather not delay for more bikeshedding. Before agreeing to LSF I'd
>>> need to see a serious proposl - what we had at the last LSF was people
>>> jumping in with half baked alternative proposals that very much hadn't
>>> been thought through, and I see no need to repeat that.
>>>
>>> Like I mentioned, there's other work gated on this patchset; if people
>>> want to hold this up for more discussion they better be putting forth
>>> something to discuss.
>>
>> I'm thinking of ways on how to achieve Michal's request: "as long as
>> there is a wider agreement from the MM community". If we can achieve
>> that without LSF, great! (a bi-weekly MM meeting might also be an option=
)
>=20
> There will be a maintenance burden even with the cleanest proposed
> approach.=20

Yes.

> We worked hard to make the patchset as clean as possible and
> if benefits still don't outweigh the maintenance cost then we should
> probably stop trying.

Indeed.

> At LSF/MM I would rather discuss functonal
> issues/requirements/improvements than alternative approaches to
> instrument allocators.
> I'm happy to arrange a separate meeting with MM folks if that would
> help to progress on the cost/benefit decision.
Note that I am only proposing ways forward.

If you think you can easily achieve what Michal requested without all=20
that, good.

My past experience was that LSF/MM / bi-weekly MM meetings were=20
extremely helpful to reach consensus.

--=20
Cheers,

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/adbb77ee-1662-4d24-bcbf-d74c29bc5083%40redhat.com.
