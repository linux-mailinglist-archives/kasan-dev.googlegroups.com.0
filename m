Return-Path: <kasan-dev+bncBC32535MUICBB2U6WKXAMGQEZSLNRBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 489158546BF
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 11:01:16 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-59a25e89211sf6884425eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 02:01:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707904875; cv=pass;
        d=google.com; s=arc-20160816;
        b=yFZrjBsVPbqDDReVGQt7wCzuqQd54be2IIo4zYdc0DNXH5r29ZF6VMqLJMy/z9rSwU
         Sr1cuq7vmNSdSy9UGPpbuuNWpG0lW1j3ewKkKXVT+FhsmQqukN8xP5kaBLIaARnoqSCx
         tmWX6qb9Y1HaDAp3GkcaWbStZU86tKoZEf535v0oY+r0jW9QP70q3d7RTxBuiwODLJi+
         PTSuebCxOyTVrbggnqbF4sIYe2gQ90ZzR3lsZc61RIJFquNFFVal3j43G9eEe/akK7XX
         Qk0kdqd9Cd2//xPRxOG4q47SvKPWdNxdvju5S8BVRqRiNn2hzzkeSzOy3eiX0POYuPy4
         P4ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=J/35tmxiKj+pYi+6nTks1CYnJLk2zJSqOUavieX9H88=;
        fh=UNb3eiITO+i8BGOMydRkznUY0Y3SjYC/jwQagahlP8I=;
        b=e0Nz0xV3a+E4PbhRFIA4JraqcK9KDQifUhw7V+QHYJhelZT5UvzWc+ssYo3h/awlLY
         MKX0LIoEoTlRdE1GdW6WAlfXixpsCeGjKj/6oId+R0PFTeuq8TLfyoXpfC9nlQdTvhEv
         I9L/8AD7LuwaAFUDApfoFIfecCQFpqdAaufmqYfvn7cEbloXu6k6sV7m2Ej/b2YMjcAf
         WvwxKIkBAapabSDfHq4OrMs6llKpfDOs7zHSVlodl+W/ck50ZQ2Z5+hQhSpWeZVbv5Gd
         ewzadX6/osRwEdgKjtAgtJacwBECr/KEraQhXOJimBRmBckY7Pe/R27+shOEgi7KpLFk
         0bVQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fAkD4SPm;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707904875; x=1708509675; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:organization:autocrypt:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=J/35tmxiKj+pYi+6nTks1CYnJLk2zJSqOUavieX9H88=;
        b=snvrkJbQ+pKdaypib40Wn0zY3UCXUhulW2R6O2z82BF9FNmv9a/EEa+ib4wohiyKUN
         8w2xc7SiGgajSQgz4okuLCXVhvPVFsv6ky/et9kJck6+R9jDIErghrXAqBFXpOIeJKS1
         u1/05BSy3wkbD5lfNz78CMQ3Jm/p4MkLeTcn+ut6AkXi1yQ/Nbh4mcpmgpTl3+Qmpy7x
         +YwBazIy7N6wI/P9ATq0gQAc+2kOKaxzoSj1zFsyuPblD6R7QlyeydeCqRnuJHzAEH2k
         1WdvZiaQrbltQBYkgDkMT+LiCV0/+IeRf9RlpNaIFTXOuUEGk2k4hVccPT0DW6DeMM1k
         6R6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707904875; x=1708509675;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=J/35tmxiKj+pYi+6nTks1CYnJLk2zJSqOUavieX9H88=;
        b=hNbwZJna37GNILwE6D/q+tOUWo/OAkg60NRFglVU2grZqPpA7kDbtS/WqN8n9ltMmW
         StJsMwYoSXGPAWgaH7xGZQdBUlewgXsv9WVXLZ0pReN6bGnnXdKcHuLrpotQ9WvLfgwb
         26FCVAvlg/aTQIssmpaeRf3RE7qoAU1x3Ok7mKL4m0kN9cU2duMSdAIuZQ+9iPXiyDtq
         S/FVctezN8En7TtdNqE8wYyFHRJDidt6KaPMWsLZY9YiIXTbMzxQ+8yucoe3dSF1vJP0
         VNUyXPjH5u96r/Yr7oXf8gXTUjfnkZyBubujfQPWetVpg2LGfv5Nd7rJMzj6BYIt/8ZR
         OcPQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWROkTwV6e2p9M0KSAgB/HBBikVIyBNy+io1/gXd1e1Wn2rImDQ4BfsRB0x1o7heLd28vFhDPbGYv9V1LZtLDzY+I0DLNuw+w==
X-Gm-Message-State: AOJu0YwtruOAObetVJLB54QE0nBow7i05k1NGxwKDq6cy7vK2xW2tyDv
	zEXPGHpvHr2JAWHMpPynFNN059F6+uqF/aFiCKbFgotArqQ+9zkQ
X-Google-Smtp-Source: AGHT+IGCwTJ7v2GqFk/axtU0zXBFfWCVH/yANLdS/lZ78OCqr7+rV9Uy8jqvFdZWayX1FOvJQabVGw==
X-Received: by 2002:a4a:ea1c:0:b0:59d:42eb:69b3 with SMTP id x28-20020a4aea1c000000b0059d42eb69b3mr2134451ood.2.1707904874780;
        Wed, 14 Feb 2024 02:01:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:af04:0:b0:599:26f9:72a8 with SMTP id w4-20020a4aaf04000000b0059926f972a8ls44583oon.0.-pod-prod-07-us;
 Wed, 14 Feb 2024 02:01:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXmNLnx4i8b3/lMba1Zj76V3RoyKbNb3HPkwp+HisMNcFPNWQf0GpgNtTN2sqB31JDR48otmQDE7xx535h1dt1dxWlssweXahNYig==
X-Received: by 2002:a05:6808:640b:b0:3c0:3389:3b33 with SMTP id fg11-20020a056808640b00b003c033893b33mr2391106oib.27.1707904873710;
        Wed, 14 Feb 2024 02:01:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707904873; cv=none;
        d=google.com; s=arc-20160816;
        b=gK57b5pt8N+dK6/pVNW2fBEHthHYc1X2HCkKZh8qt47r3lJss2caXYAaKBciePG8UX
         22RNbUM+USLgn4jj4w5vsn930k+5FS9n2/GN+fDCdyg/dKaJkiktuy0oujdiinCdKJnO
         2Fjd0S/9zkkzfOQ6LajiIpK3/Oh6wVy73b8RBf5iMnBhlNZ85YHNmoYoRCMW11jtyaf8
         lFgcAgksG09ywNQno9qO29/4COfc/VYC8SscWNRsFeFeP27aOEUq/wyD1ZkTaZAty/JT
         I7JR6vgweDgU9Yfy7DLo1XSrll4/IXYSgOtmjYasbCftZvOytE7B25dZJ6TqrG6v3JoH
         vXBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=SYtqzgv+BxOcacLu4368aIKcl3CwnG8tHFk8B9VUFvU=;
        fh=Pqyvjc/jgxpg6gsPXB92t9045c/fpYXQJPp7NWhDN9I=;
        b=I9m9xZh3QQgcxO4rgbZKdtgls8yUs8OmuLJ2T811utOH0iAhmsw58jZyNhg8jkNEfo
         N3E5dBNwMoTtdU0kcWhes6FiavJJfGKLVka7uUOUJyvSQCQ49QqJQ2NtdlJ/+TxK2/I7
         HdnltXMCvdRLQqDZEJh2NtUTYkACXIlln8pMTb+s2HqWanMfQxICBgCZTEpuwyBK45oh
         DyB26W3IYzCJuhsKy5tu7ynDNQEqVmT2vWZBfWA0dBbEZv8Z7MWLjS+eFK2VdZKfV2W4
         kYIApJvFx7eVsaj/2PvnnJeInizLtXNJoJD1LmcIknkBbvCOeAeAWPlXQqdBB7IjaTkv
         53cA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fAkD4SPm;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
X-Forwarded-Encrypted: i=1; AJvYcCU5Mfs6tiIejeR8AWy1ED5Tm2eBB8lKtMBO/UNdnYmn+EvJkHdUZmKc4Qupf8zW6z6iK9nxh122Yh18qK+BfLRZXMdVPvwAzwDmSA==
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id ku21-20020a056808709500b003c041e74e41si385586oib.5.2024.02.14.02.01.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Feb 2024 02:01:13 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-lj1-f198.google.com (mail-lj1-f198.google.com
 [209.85.208.198]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-601-CiNnKFiJPQqeEikj8OcUYQ-1; Wed, 14 Feb 2024 05:01:08 -0500
X-MC-Unique: CiNnKFiJPQqeEikj8OcUYQ-1
Received: by mail-lj1-f198.google.com with SMTP id 38308e7fff4ca-2d0a3bcfb11so52025111fa.3
        for <kasan-dev@googlegroups.com>; Wed, 14 Feb 2024 02:01:08 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVIxYJ9Siv+z3kquOZwwr/ZZD+XavomVHTdVrB5kuNXQhnl5FBRYOGWqJ34g4zOo3NTX2l5/ooe+CNiMy6jZ5JZfHzZIvy9+crqpA==
X-Received: by 2002:a2e:bb85:0:b0:2d0:de72:9d47 with SMTP id y5-20020a2ebb85000000b002d0de729d47mr1387356lje.8.1707904866644;
        Wed, 14 Feb 2024 02:01:06 -0800 (PST)
X-Received: by 2002:a2e:bb85:0:b0:2d0:de72:9d47 with SMTP id y5-20020a2ebb85000000b002d0de729d47mr1387286lje.8.1707904866113;
        Wed, 14 Feb 2024 02:01:06 -0800 (PST)
Received: from ?IPV6:2003:d8:2f3c:3f00:7177:eb0c:d3d2:4b0e? (p200300d82f3c3f007177eb0cd3d24b0e.dip0.t-ipconnect.de. [2003:d8:2f3c:3f00:7177:eb0c:d3d2:4b0e])
        by smtp.gmail.com with ESMTPSA id z21-20020a05600c221500b004101f27737asm1416372wml.29.2024.02.14.02.01.02
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Feb 2024 02:01:05 -0800 (PST)
Message-ID: <d7d132ca-8d0d-497e-bf8d-3c275960aaf9@redhat.com>
Date: Wed, 14 Feb 2024 11:01:02 +0100
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
 <c842347d-5794-4925-9b95-e9966795b7e1@redhat.com>
 <CAJuCfpFB-WimQoC1s-ZoiAx+t31KRu1Hd9HgH3JTMssnskdvNw@mail.gmail.com>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <CAJuCfpFB-WimQoC1s-ZoiAx+t31KRu1Hd9HgH3JTMssnskdvNw@mail.gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=fAkD4SPm;
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

On 14.02.24 00:28, Suren Baghdasaryan wrote:
> On Tue, Feb 13, 2024 at 3:22=E2=80=AFPM David Hildenbrand <david@redhat.c=
om> wrote:
>>
>> On 14.02.24 00:12, Kent Overstreet wrote:
>>> On Wed, Feb 14, 2024 at 12:02:30AM +0100, David Hildenbrand wrote:
>>>> On 13.02.24 23:59, Suren Baghdasaryan wrote:
>>>>> On Tue, Feb 13, 2024 at 2:50=E2=80=AFPM Kent Overstreet
>>>>> <kent.overstreet@linux.dev> wrote:
>>>>>>
>>>>>> On Tue, Feb 13, 2024 at 11:48:41PM +0100, David Hildenbrand wrote:
>>>>>>> On 13.02.24 23:30, Suren Baghdasaryan wrote:
>>>>>>>> On Tue, Feb 13, 2024 at 2:17=E2=80=AFPM David Hildenbrand <david@r=
edhat.com> wrote:
>>>>>>>>>
>>>>>>>>> On 13.02.24 23:09, Kent Overstreet wrote:
>>>>>>>>>> On Tue, Feb 13, 2024 at 11:04:58PM +0100, David Hildenbrand wrot=
e:
>>>>>>>>>>> On 13.02.24 22:58, Suren Baghdasaryan wrote:
>>>>>>>>>>>> On Tue, Feb 13, 2024 at 4:24=E2=80=AFAM Michal Hocko <mhocko@s=
use.com> wrote:
>>>>>>>>>>>>>
>>>>>>>>>>>>> On Mon 12-02-24 13:38:46, Suren Baghdasaryan wrote:
>>>>>>>>>>>>> [...]
>>>>>>>>>>>>>> We're aiming to get this in the next merge window, for 6.9. =
The feedback
>>>>>>>>>>>>>> we've gotten has been that even out of tree this patchset ha=
s already
>>>>>>>>>>>>>> been useful, and there's a significant amount of other work =
gated on the
>>>>>>>>>>>>>> code tagging functionality included in this patchset [2].
>>>>>>>>>>>>>
>>>>>>>>>>>>> I suspect it will not come as a surprise that I really dislik=
e the
>>>>>>>>>>>>> implementation proposed here. I will not repeat my arguments,=
 I have
>>>>>>>>>>>>> done so on several occasions already.
>>>>>>>>>>>>>
>>>>>>>>>>>>> Anyway, I didn't go as far as to nak it even though I _strong=
ly_ believe
>>>>>>>>>>>>> this debugging feature will add a maintenance overhead for a =
very long
>>>>>>>>>>>>> time. I can live with all the downsides of the proposed imple=
mentation
>>>>>>>>>>>>> _as long as_ there is a wider agreement from the MM community=
 as this is
>>>>>>>>>>>>> where the maintenance cost will be payed. So far I have not s=
een (m)any
>>>>>>>>>>>>> acks by MM developers so aiming into the next merge window is=
 more than
>>>>>>>>>>>>> little rushed.
>>>>>>>>>>>>
>>>>>>>>>>>> We tried other previously proposed approaches and all have the=
ir
>>>>>>>>>>>> downsides without making maintenance much easier. Your positio=
n is
>>>>>>>>>>>> understandable and I think it's fair. Let's see if others see =
more
>>>>>>>>>>>> benefit than cost here.
>>>>>>>>>>>
>>>>>>>>>>> Would it make sense to discuss that at LSF/MM once again, espec=
ially
>>>>>>>>>>> covering why proposed alternatives did not work out? LSF/MM is =
not "too far"
>>>>>>>>>>> away (May).
>>>>>>>>>>>
>>>>>>>>>>> I recall that the last LSF/MM session on this topic was a bit u=
nfortunate
>>>>>>>>>>> (IMHO not as productive as it could have been). Maybe we can fi=
nally reach a
>>>>>>>>>>> consensus on this.
>>>>>>>>>>
>>>>>>>>>> I'd rather not delay for more bikeshedding. Before agreeing to L=
SF I'd
>>>>>>>>>> need to see a serious proposl - what we had at the last LSF was =
people
>>>>>>>>>> jumping in with half baked alternative proposals that very much =
hadn't
>>>>>>>>>> been thought through, and I see no need to repeat that.
>>>>>>>>>>
>>>>>>>>>> Like I mentioned, there's other work gated on this patchset; if =
people
>>>>>>>>>> want to hold this up for more discussion they better be putting =
forth
>>>>>>>>>> something to discuss.
>>>>>>>>>
>>>>>>>>> I'm thinking of ways on how to achieve Michal's request: "as long=
 as
>>>>>>>>> there is a wider agreement from the MM community". If we can achi=
eve
>>>>>>>>> that without LSF, great! (a bi-weekly MM meeting might also be an=
 option)
>>>>>>>>
>>>>>>>> There will be a maintenance burden even with the cleanest proposed
>>>>>>>> approach.
>>>>>>>
>>>>>>> Yes.
>>>>>>>
>>>>>>>> We worked hard to make the patchset as clean as possible and
>>>>>>>> if benefits still don't outweigh the maintenance cost then we shou=
ld
>>>>>>>> probably stop trying.
>>>>>>>
>>>>>>> Indeed.
>>>>>>>
>>>>>>>> At LSF/MM I would rather discuss functonal
>>>>>>>> issues/requirements/improvements than alternative approaches to
>>>>>>>> instrument allocators.
>>>>>>>> I'm happy to arrange a separate meeting with MM folks if that woul=
d
>>>>>>>> help to progress on the cost/benefit decision.
>>>>>>> Note that I am only proposing ways forward.
>>>>>>>
>>>>>>> If you think you can easily achieve what Michal requested without a=
ll that,
>>>>>>> good.
>>>>>>
>>>>>> He requested something?
>>>>>
>>>>> Yes, a cleaner instrumentation. Unfortunately the cleanest one is not
>>>>> possible until the compiler feature is developed and deployed. And it
>>>>> still would require changes to the headers, so don't think it's worth
>>>>> delaying the feature for years.
>>>>>
>>>>
>>>> I was talking about this: "I can live with all the downsides of the pr=
oposed
>>>> implementationas long as there is a wider agreement from the MM commun=
ity as
>>>> this is where the maintenance cost will be payed. So far I have not se=
en
>>>> (m)any acks by MM developers".
>>>>
>>>> I certainly cannot be motivated at this point to review and ack this,
>>>> unfortunately too much negative energy around here.
>>>
>>> David, this kind of reaction is exactly why I was telling Andrew I was
>>> going to submit this as a direct pull request to Linus.
>>>
>>> This is an important feature; if we can't stay focused ot the technical
>>> and get it done that's what I'll do.
>>
>> Kent, I started this with "Would it make sense" in an attempt to help
>> Suren and you to finally make progress with this, one way or the other.
>> I know that there were ways in the past to get the MM community to agree
>> on such things.
>>
>> I tried to be helpful, finding ways *not having to* bypass the MM
>> community to get MM stuff merged.
>>
>> The reply I got is mostly negative energy.
>>
>> So you don't need my help here, understood.
>>
>> But I will fight against any attempts to bypass the MM community.
>=20
> Well, I'm definitely not trying to bypass the MM community, that's why
> this patchset is posted. Not sure why people can't voice their opinion
> on the benefit/cost balance of the patchset over the email... But if a
> meeting would be more productive I'm happy to set it up.

If you can get the acks without any additional meetings, great. The=20
replies from Pasha and Johannes are encouraging, let's hope core=20
memory-allocator people will voice their opinion here.

If you come to the conclusion that another meeting would help getting=20
maintainers's attention and sorting out some of the remaining concerns,=20
feel free to schedule a meeting with Dave R. I suspect only the slot=20
next week is already taken. In the past, we also had "special" meetings=20
just for things to make progress faster.

If you're looking for ideas on what the agenda of such a meeting could=20
look like, I'll happily discuss that with you off-list.

v2 was more than 3 months ago. If it's really about minor details here,=20
waiting another 3 months for LSF/MM is indeed not reasonable.

Myself, I'll be happy not having to sit through another LSF/MM session=20
of that kind. The level of drama is exceptional and I'm hoping it won't=20
be the new norm in the MM space.

Good luck!

--=20
Cheers,

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/d7d132ca-8d0d-497e-bf8d-3c275960aaf9%40redhat.com.
