Return-Path: <kasan-dev+bncBC32535MUICBBBGVV6XAMGQEB33WK3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id A02B8853E6D
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 23:17:41 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-42c739603b0sf645241cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 14:17:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707862660; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z8gH9Utu8b8OJ4MSS6rh8hDqUelYhHAk2FlwfqyIV3IhS7HvSuvNL7guibXQHGTjNp
         NOAR2IOkf1qPxl8uloVuGRxqScERdgv/kCZYDBgaVIps/gO+QfjDDOGN7gpM2w7NzaLq
         zNZUvysAhUZ0uLRLZd9upmOc1I9hW4Fh3OQCzW5DOcuRuy+r5Kwu88p6HB8dMNosY2kV
         ruUwUeizCGox6CfKgZh+MVwTr2w8O6e0123/Y0Sz5omIWdbymmWAtV7rbcglWY8RrXgc
         6Qr4sp5kV39nyOVg8Ze8y6WIryz3bRRJGMQUTtWHbloHMMx35fQDWsvTgjDgH0ZucCJg
         +3+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=Tp7aEjGVkaJdAIhZpydFJthDWQlTnQR6E0dAQwpe4hU=;
        fh=Lbe0+HrEsOo+aLh2CmVuwcODVew4Sp0DCj+PhBsjZmA=;
        b=ktYK5/oHheeApM4nXFgopbNZDwa6OGl+h7RUcnMX7pAdjuLrJqCa1FHMaQH36LlzvC
         7JadArHyOLB/XPEj5MrjYX1MEiJ0C0lU9KgscS5K2/GbhTvipfxHZ78NOt6oKO/gLwDy
         iLzVsdCykonJlN+S4Armk6v/x9LLHLXheyj+qAaXTED8M47ICcnAxDjBMnURzm3BMYk8
         ScDYTwUSCun5tuWfH1Yq+aNFbXRDN/6iTlT6D7cCFP0F66dci8yPKa/w0wvceSUYi0qz
         sdyv4KJX2GwQKsyc896Br/4rbl+6ZE43gpWP+E/pHFQtd/f5XdZccNlEQfs5nIoh5mo6
         c1ZA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=iRPAZtKi;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707862660; x=1708467460; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:organization:autocrypt:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Tp7aEjGVkaJdAIhZpydFJthDWQlTnQR6E0dAQwpe4hU=;
        b=t6VLWHlk/mYfoVh7zyAgi+Bcok8FQCUpR00/08Yv/fV7PY3amJzlTt3NLyPhauhJsS
         lUaoeJrGjOhwxG3jOXLKqX/x5DfrLaKqQe0Gk9ClmfLwm0mPD+4kDXF/Y5TaM41d71C7
         zPWYp5HYwbU1r6PGJEKXnI2o7Q6noKg9C1tXjasGWseks7FDdF+pfWtHQ1grT9StfDWD
         4/QvOFP6KlWG5g3f749tkx87p8OGMrpS24LSl78vLRPZcPlpFTwSGgOSybvKgzjSMAmw
         3MQV9Q00jRIaLtjbBIOFO4obVqugH7pddWLByDWPnu+8oV+NmcVEfWuuERJ1scAC+SID
         nsXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707862660; x=1708467460;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Tp7aEjGVkaJdAIhZpydFJthDWQlTnQR6E0dAQwpe4hU=;
        b=LCl95EfKGpbdetsfvcwJsWUYmEr15qh0FQCPHOb5wHTmxd5Lv9MmPwJLybMDodaVNx
         QGDmuTYEGAbtS4Haj6h8WaQPl1VQkrxsLt2qMlDhKvxFqXN2qr6Oy7n2+ypO5eLRVVID
         X+Q4Hlbyw9ia1u4sZlSx4E5VI5Ubt2Tvvi+qWJYc2WsNMPE5iUU1F/ib/f05gEzzYgWm
         7y+rRtNSF/RqmkHt9+P0HfqqZQ/54eiJW44Sp3PAKhuxc8jGwa1WFbZ8mCiEHf2tpIXb
         GnuXU3CYkVDTuA3fMdYo1OPtY9RcX9t91BanU+cXXyCIiNDa7GbnZgbX1OYMssho160w
         u7Nw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX4dI8cUtBjV9VCDZqj1UeGzemS3w8PopFey2aNo6barF0IF3hNwxT/z2zZrmHnLTQWE13CTtish7unaLC+JYjkE2auICc+HA==
X-Gm-Message-State: AOJu0YxVx5Skrx0a7sYtDjEYX7mSZaVKn++ZWMDp2P2JZWBUs4HtPJn2
	kG3V46rqMLOaadFkObShUjDB1A2yxjPteAXcepe9bhxQFGI6Hj5E
X-Google-Smtp-Source: AGHT+IHxxlteNrT0kzktGIRCaPPP7KGqoLm7zo0KY0eg6Iv7xZUg7yseBCKZuIpNm64Gl/2Ifd/J2A==
X-Received: by 2002:ac8:4614:0:b0:42c:2706:bad4 with SMTP id p20-20020ac84614000000b0042c2706bad4mr60504qtn.27.1707862660472;
        Tue, 13 Feb 2024 14:17:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:58d0:0:b0:59a:98a2:b1f4 with SMTP id f199-20020a4a58d0000000b0059a98a2b1f4ls3048382oob.1.-pod-prod-02-us;
 Tue, 13 Feb 2024 14:17:39 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXRPJSxISjEiZybm/Qy5oguj0/7pGYmrd5re0YeW1AkifVTnBAyHfQCdRg1oPdJbiY2lv9LOB52cF6gBmB76MHmCySnC14ShefZ1Q==
X-Received: by 2002:a9d:7359:0:b0:6e2:dfe4:5502 with SMTP id l25-20020a9d7359000000b006e2dfe45502mr1134249otk.0.1707862659321;
        Tue, 13 Feb 2024 14:17:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707862659; cv=none;
        d=google.com; s=arc-20160816;
        b=r/6lxejqSiz1NLnGWr5MI1Z6uIjZX5FhfhuzoIhHWCRPFMRVyPPa6jX4NtNoT449Vm
         OehUP+N6bbSmEkqlx6KbRXACFgb8agtFA0NbbruG8/rxM8+jwYUqv0gEuDa9BpoLSIRO
         uUeeb7DOjCUOq6m6za4GxoW+c83Uw+PFZ4Tt0aLrZ6byaWHu/4hrlXT47HSdTCkyIaqQ
         GL98OTF2h7bfTSfG5QOaws1JSPkoL7s9tugcdUdBEsY9pT40A3k+9ZPVyHB2Zq4S7HgZ
         JMgs9XODJ8qG8Dg45MpB2izJnr8icbmW6z2gBKlwUUNznJ3uw76iGCGYbfyPuEZco25n
         kp1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=eCcHtaszOKE9Vsf07irwuhOuZ163lqjSaVd6CZ9ODTE=;
        fh=dZNTKlqJg2GwRwWLliS+R9cnMZiQmY+swY8fL7NIyqs=;
        b=d1XVXBm5cJw1tpOqL7xYZr1m8kBKJR+cdpXbaFew3w0BYSMx44lPASKNpSR8jToF3X
         tWL1VcXrZWacm/cT9WIbW+v4XmUnUO/ed5J5+0U5n8uNGMOhad+9LKrwC2SscQb9CRk3
         6ySdq2FMXKdFxDrg+AhZyJCyBRQRAw8zxkHIzGqcBWZR/4IxP8NiqmgLNF90v7vJOf1s
         8OqdZEpxLM/3GJ/m3T1SddAXrIkv7DvmdLlzvXMVdkv8neiRkixJIrb38O5mljR93Gil
         fgDeQ0uOwfxlSjL2/dQZff4QO6m8LnsKUH7U8F/nfZY6YIeAJCr7xhXJ7CIE+veZVwhM
         bP2g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=iRPAZtKi;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
X-Forwarded-Encrypted: i=1; AJvYcCW3k50eFoAny8u7e+nt4RrX3yuTQf6XB55NcNBf0RTNj9Fqyyu9P+UYYJEfwdXeQBxx8GggoyToj/unpDIFpZF+XYPIAZUZ/DfxAg==
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id en15-20020a056830488f00b006e2db0e0043si392833otb.5.2024.02.13.14.17.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Feb 2024 14:17:39 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-417-L9KDlVO3PTmYcl3yGPsAag-1; Tue, 13 Feb 2024 17:17:37 -0500
X-MC-Unique: L9KDlVO3PTmYcl3yGPsAag-1
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-411e1466370so650705e9.0
        for <kasan-dev@googlegroups.com>; Tue, 13 Feb 2024 14:17:37 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWP/gPmUG98wy+5T/LQTC8k+dzjXrWMmoO/fBxA5rkd/+PcDTyuIP2Eo8TQ8B8I92Q38dKGdpCaJe/9s31mdj9d/UrCUQ3bW1mkMQ==
X-Received: by 2002:a05:6000:104c:b0:33c:ddf4:742e with SMTP id c12-20020a056000104c00b0033cddf4742emr417678wrx.22.1707862656067;
        Tue, 13 Feb 2024 14:17:36 -0800 (PST)
X-Received: by 2002:a05:6000:104c:b0:33c:ddf4:742e with SMTP id c12-20020a056000104c00b0033cddf4742emr417626wrx.22.1707862655588;
        Tue, 13 Feb 2024 14:17:35 -0800 (PST)
X-Forwarded-Encrypted: i=1; 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
Received: from ?IPV6:2003:d8:2f3c:3f00:7177:eb0c:d3d2:4b0e? (p200300d82f3c3f007177eb0cd3d24b0e.dip0.t-ipconnect.de. [2003:d8:2f3c:3f00:7177:eb0c:d3d2:4b0e])
        by smtp.gmail.com with ESMTPSA id f14-20020a056000128e00b0033b50e0d493sm10564789wrx.59.2024.02.13.14.17.33
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Feb 2024 14:17:35 -0800 (PST)
Message-ID: <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com>
Date: Tue, 13 Feb 2024 23:17:32 +0100
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
References: <20240212213922.783301-1-surenb@google.com>
 <Zctfa2DvmlTYSfe8@tiehlicka>
 <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
 <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com>
 <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=iRPAZtKi;
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

On 13.02.24 23:09, Kent Overstreet wrote:
> On Tue, Feb 13, 2024 at 11:04:58PM +0100, David Hildenbrand wrote:
>> On 13.02.24 22:58, Suren Baghdasaryan wrote:
>>> On Tue, Feb 13, 2024 at 4:24=E2=80=AFAM Michal Hocko <mhocko@suse.com> =
wrote:
>>>>
>>>> On Mon 12-02-24 13:38:46, Suren Baghdasaryan wrote:
>>>> [...]
>>>>> We're aiming to get this in the next merge window, for 6.9. The feedb=
ack
>>>>> we've gotten has been that even out of tree this patchset has already
>>>>> been useful, and there's a significant amount of other work gated on =
the
>>>>> code tagging functionality included in this patchset [2].
>>>>
>>>> I suspect it will not come as a surprise that I really dislike the
>>>> implementation proposed here. I will not repeat my arguments, I have
>>>> done so on several occasions already.
>>>>
>>>> Anyway, I didn't go as far as to nak it even though I _strongly_ belie=
ve
>>>> this debugging feature will add a maintenance overhead for a very long
>>>> time. I can live with all the downsides of the proposed implementation
>>>> _as long as_ there is a wider agreement from the MM community as this =
is
>>>> where the maintenance cost will be payed. So far I have not seen (m)an=
y
>>>> acks by MM developers so aiming into the next merge window is more tha=
n
>>>> little rushed.
>>>
>>> We tried other previously proposed approaches and all have their
>>> downsides without making maintenance much easier. Your position is
>>> understandable and I think it's fair. Let's see if others see more
>>> benefit than cost here.
>>
>> Would it make sense to discuss that at LSF/MM once again, especially
>> covering why proposed alternatives did not work out? LSF/MM is not "too =
far"
>> away (May).
>>
>> I recall that the last LSF/MM session on this topic was a bit unfortunat=
e
>> (IMHO not as productive as it could have been). Maybe we can finally rea=
ch a
>> consensus on this.
>=20
> I'd rather not delay for more bikeshedding. Before agreeing to LSF I'd
> need to see a serious proposl - what we had at the last LSF was people
> jumping in with half baked alternative proposals that very much hadn't
> been thought through, and I see no need to repeat that.
>=20
> Like I mentioned, there's other work gated on this patchset; if people
> want to hold this up for more discussion they better be putting forth
> something to discuss.

I'm thinking of ways on how to achieve Michal's request: "as long as=20
there is a wider agreement from the MM community". If we can achieve=20
that without LSF, great! (a bi-weekly MM meeting might also be an option)

--=20
Cheers,

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/6a0f5d8b-9c67-43f6-b25e-2240171265be%40redhat.com.
