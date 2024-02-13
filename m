Return-Path: <kasan-dev+bncBC32535MUICBBD7KV6XAMGQE5PXRYOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 251DF853F9D
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 00:02:41 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-362cfc117ecsf199085ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 15:02:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707865359; cv=pass;
        d=google.com; s=arc-20160816;
        b=wx/Ay3QX+ooQedjI0K0pXg1J5ZZOySkI5mAnlP1bQ39zJFIKf/qfyWPNjFkHFhqXem
         7tbg7mG5Vrl+f9Q8unQEYWBLjnwaTzs/F+HdQp29a3B2odtgorlBsGApXy37yN7EPjps
         Dg00txHmHHjQbaitCmYWooi79YERG09I0apwCodVtfS4gWnVZQQa1Ks8gWtpuwC7zh2r
         8xgBxmq9oGAlaYnIPLded/b6ZdzaL72fKSsJYPuw6u/c7w3pHvaBfi/3TL/1mwNiwGkj
         O20VRYmksOH7XodzHKNV/tvynH7TRuMUIGqGXkvRZsrWkyoIENBHx6TOnzDryxG9Hyh1
         t/rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=U1QiciEhPo61qFKfcNupqHs6bQ18eofho03GQq/aAuE=;
        fh=u+jmGTdcy4yk+pSfQKP5d6BuR8RhvvVVTaahVKSl2hE=;
        b=S76wLZdSGFtJLSyVU8wFYyc/sDN1ukNDEIIPLafaRyyGBhG/O2b6vFigVPzUuh93GQ
         aFOsZWz7Tr/YIO7q+UfrN3d/Sw+ZOrWUZFu7HTtMkzjgC2a+BGMBhkJ+LgTiW6uRgecA
         wkgMuTejQN8hMMQw5gAFJnZTb+wpx2c8aFC+gAQrvaEKXD2uFPP8qzCo/sOkqklxNgnz
         zuCobqtUwGBZVNvsy84r7V64DRPuCxgSOszyP657b0GMTDBy0vWNVZNhkXB4GK0OwpgH
         obe1GaD1r5hHufO/7GpRLwIdSZNVXlceSIG4vW0fgKj2y+gAOTLLKiCIwq++UbGm23xy
         6b/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=gezmn6R4;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707865359; x=1708470159; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:organization:autocrypt:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=U1QiciEhPo61qFKfcNupqHs6bQ18eofho03GQq/aAuE=;
        b=io+JWi+0tf45GJQu12Z5CVKEYdTmIc8DQkPE6etWPRl/pGZtuDC9wslnRviYogFYOw
         FGgk3v2WS/Mbvllg+rTvN/OpGPBa8qYn+2YdaDboT+g/0lwklPpZxu16mTNGYN/O1TbN
         6SFlk6c6OvuACVnrstZ++iYqBFUZhl/7CFK+kOE34glQYKkguzSiaL6JwS4dkNAkF2RD
         G3dcXFTaK+7nALHM0rHoL7twFQCg9rHdEKLx9PTFZUKh6ligDVe8Xv42EWC5CZGuIQuA
         c+y59Z0+VSkDMKcd65hENl2XymN7dXuFZzNUugdDIAbOL9TG2xp/DDcrYWKVoSUdF6F5
         VnXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707865359; x=1708470159;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=U1QiciEhPo61qFKfcNupqHs6bQ18eofho03GQq/aAuE=;
        b=UXgmfxOKqLZlnDPlp0ZzcckJcyT+8L5zpR7tSSQh5hwJQf3CO+ahqu134/0RLfir9U
         KqMC3fGd22z4+xmKWHF9Axlfz0XWi6+e+hpKBB4LbY2TQ5ltjdLtDeaCwF2B+VksABZu
         GzGfk5NZC6qzSqQZlsb1dydw8J0j1dwbClh4ccBvL1BagIJm9QQgrPMLqEdNu9IR904V
         GoL+KGc0OVgBxNUylln/d6u/mBTW8Dj/TxG7x1kdT3AdXGDJNrJAPOEqzgoiu6RxTtcb
         TLUj7H2MoHNGXu84bY2efIR0Vb/wRnFJs+WIAeLx5wsb9mcfoJvKfHtTo9/NuqAtf+NG
         QOUA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW2yoDUGhPWXxrakZAF8HIPPT7NKfJf+xEcgLSzHFbRiFjNTqD3nzsqlL7rNVj3uMx6ImeO6k/P3wgwZ+MLfNzSF96AXFTLxQ==
X-Gm-Message-State: AOJu0Yx0Z1H2P5bMUIkacXXgn2fHWTmbvUt34ASxHXewkeU+raILksi2
	Zx983fWvgw3IQHjHCeeNQZltLk9DBpgXLikELDgOnkDOWIR/+rTe
X-Google-Smtp-Source: AGHT+IH3fWSsexo8zHlV1xp1jLXkLtbzMUh1kWyQOdbuG6tev5bsy9ypryoiXfTlnOSfcdjZ45uKKw==
X-Received: by 2002:a92:b74f:0:b0:364:2d98:c571 with SMTP id c15-20020a92b74f000000b003642d98c571mr10608ilm.19.1707865359717;
        Tue, 13 Feb 2024 15:02:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2608:b0:363:d634:8952 with SMTP id
 by8-20020a056e02260800b00363d6348952ls2674712ilb.0.-pod-prod-08-us; Tue, 13
 Feb 2024 15:02:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVLle6URLIIdnQxiKKuLMbC4vHdFMqOLFDMFpUCcgNRBGy/Q7rJZTDVhm6+p6Vg1POz/AYJuT3RVIeiIduRtTh9ODZ/vG9owrTcig==
X-Received: by 2002:a05:6602:2dcf:b0:7c4:4be7:777 with SMTP id l15-20020a0566022dcf00b007c44be70777mr1218408iow.18.1707865357513;
        Tue, 13 Feb 2024 15:02:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707865357; cv=none;
        d=google.com; s=arc-20160816;
        b=uf5fGz2uMPq3Yru3sJ2FQxd34LX3zJwU4mpJCEpOYn0nNuWPCp6hXt/RFgfARNDBfm
         VabygLR6Kezigse3paMYOpUj8SzI7NN2b+BL3Bs8dywILnun+1OR/9ebtKMYiyDQE20X
         ie19qxKkLgjSJh4q2EhAGlzcCxpYHUoxNF8rhQY7pUeam+TgXZ9oKJ5GLYB0XQsC/dCT
         aa4PGc1HKkO/siVZwr4NRep8SCaw6HeVME+7CY0GoGlJazd1rzBwi0PfoRTkodrXemhh
         1I3xIa01ftkvBXW+xWAdKgSv0Fv5da4C0dD77iiQwYMCyFEZzrhyhOEhAh7hRJxHeoph
         mvIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=xJhJ4xEMtOy5c1y6MqLIa8bGWYDGFy49+SYmZWzszOg=;
        fh=uwqTf27zv7m9+GmpYsQp0RqHtV9RU4El1B2T0+/cZK8=;
        b=clxPBNaJwnD3FHJmZW+9q2y+FRDpJ/FFAXfJPB6oFUgQMxxVAFML3QqplXuDub+Bsh
         0RlsZHDgkQoXpcK/5pSoahQPcrK5+CT1RHmklKGvwmDdWR5Q3JmkMUKh1u/OIveXsvKH
         KTYh4aFEuVrli4U5LhM9ElJvbUyc86lU3u6AOqPr936AOBaivgMJt8H3mOxxBJPfCLpA
         PLRH/5BSri8YuqdxseC8Ay+lkUBjico5oMNV+HSnpj3t2KWuSrYUuFjOF2RC1NK+bIM9
         dNpD0iHoVDP+eoS5tY5mSjjUelsj3rKRkEkA/zyNJ2HCGhfyrQuIocbZhP4lWB4FDdFB
         CUSQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=gezmn6R4;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
X-Forwarded-Encrypted: i=1; AJvYcCUlN4bmnA5nGSmwybH40h7BnxEGyKozg7Hg2/4DaspIIjAzyjIgAoXJJd2HcTiLVleVqP5rleScSBULM8qlCpuYdaDklVSrK5w2Wg==
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id v13-20020a02384d000000b00473ac84c0c0si555536jae.6.2024.02.13.15.02.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Feb 2024 15:02:37 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f71.google.com (mail-wr1-f71.google.com
 [209.85.221.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-186-BaHUgVz5PY2YJZxcJGQy5g-1; Tue, 13 Feb 2024 18:02:35 -0500
X-MC-Unique: BaHUgVz5PY2YJZxcJGQy5g-1
Received: by mail-wr1-f71.google.com with SMTP id ffacd0b85a97d-33b316fcaecso1814369f8f.3
        for <kasan-dev@googlegroups.com>; Tue, 13 Feb 2024 15:02:34 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXMwKn8Mme1j+G9o0dX5MSwCFwoj2Ia1KY64gZ5Z25A6uIeZkCyr7zo8TjOgv1NHHLKcLsFzu0zUDSPheH3+5F8e7ZBOgvIpkvotQ==
X-Received: by 2002:a5d:4b44:0:b0:33c:df3e:a5a4 with SMTP id w4-20020a5d4b44000000b0033cdf3ea5a4mr459840wrs.18.1707865354008;
        Tue, 13 Feb 2024 15:02:34 -0800 (PST)
X-Received: by 2002:a5d:4b44:0:b0:33c:df3e:a5a4 with SMTP id w4-20020a5d4b44000000b0033cdf3ea5a4mr459818wrs.18.1707865353562;
        Tue, 13 Feb 2024 15:02:33 -0800 (PST)
X-Forwarded-Encrypted: i=1; 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
Received: from ?IPV6:2003:d8:2f3c:3f00:7177:eb0c:d3d2:4b0e? (p200300d82f3c3f007177eb0cd3d24b0e.dip0.t-ipconnect.de. [2003:d8:2f3c:3f00:7177:eb0c:d3d2:4b0e])
        by smtp.gmail.com with ESMTPSA id r3-20020adfca83000000b0033cdbe335bcsm2512992wrh.71.2024.02.13.15.02.30
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Feb 2024 15:02:33 -0800 (PST)
Message-ID: <a9b0440b-844e-4e45-a546-315d53322aad@redhat.com>
Date: Wed, 14 Feb 2024 00:02:30 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
To: Suren Baghdasaryan <surenb@google.com>,
 Kent Overstreet <kent.overstreet@linux.dev>
Cc: Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org,
 vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
 mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
 liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
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
 <adbb77ee-1662-4d24-bcbf-d74c29bc5083@redhat.com>
 <r6cmbcmalryodbnlkmuj2fjnausbcysmolikjguqvdwkngeztq@45lbvxjavwb3>
 <CAJuCfpF4g1jeEwHVHjQWwi5kqS-3UqjMt7GnG0Kdz5VJGyhK3Q@mail.gmail.com>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <CAJuCfpF4g1jeEwHVHjQWwi5kqS-3UqjMt7GnG0Kdz5VJGyhK3Q@mail.gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=gezmn6R4;
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

On 13.02.24 23:59, Suren Baghdasaryan wrote:
> On Tue, Feb 13, 2024 at 2:50=E2=80=AFPM Kent Overstreet
> <kent.overstreet@linux.dev> wrote:
>>
>> On Tue, Feb 13, 2024 at 11:48:41PM +0100, David Hildenbrand wrote:
>>> On 13.02.24 23:30, Suren Baghdasaryan wrote:
>>>> On Tue, Feb 13, 2024 at 2:17=E2=80=AFPM David Hildenbrand <david@redha=
t.com> wrote:
>>>>>
>>>>> On 13.02.24 23:09, Kent Overstreet wrote:
>>>>>> On Tue, Feb 13, 2024 at 11:04:58PM +0100, David Hildenbrand wrote:
>>>>>>> On 13.02.24 22:58, Suren Baghdasaryan wrote:
>>>>>>>> On Tue, Feb 13, 2024 at 4:24=E2=80=AFAM Michal Hocko <mhocko@suse.=
com> wrote:
>>>>>>>>>
>>>>>>>>> On Mon 12-02-24 13:38:46, Suren Baghdasaryan wrote:
>>>>>>>>> [...]
>>>>>>>>>> We're aiming to get this in the next merge window, for 6.9. The =
feedback
>>>>>>>>>> we've gotten has been that even out of tree this patchset has al=
ready
>>>>>>>>>> been useful, and there's a significant amount of other work gate=
d on the
>>>>>>>>>> code tagging functionality included in this patchset [2].
>>>>>>>>>
>>>>>>>>> I suspect it will not come as a surprise that I really dislike th=
e
>>>>>>>>> implementation proposed here. I will not repeat my arguments, I h=
ave
>>>>>>>>> done so on several occasions already.
>>>>>>>>>
>>>>>>>>> Anyway, I didn't go as far as to nak it even though I _strongly_ =
believe
>>>>>>>>> this debugging feature will add a maintenance overhead for a very=
 long
>>>>>>>>> time. I can live with all the downsides of the proposed implement=
ation
>>>>>>>>> _as long as_ there is a wider agreement from the MM community as =
this is
>>>>>>>>> where the maintenance cost will be payed. So far I have not seen =
(m)any
>>>>>>>>> acks by MM developers so aiming into the next merge window is mor=
e than
>>>>>>>>> little rushed.
>>>>>>>>
>>>>>>>> We tried other previously proposed approaches and all have their
>>>>>>>> downsides without making maintenance much easier. Your position is
>>>>>>>> understandable and I think it's fair. Let's see if others see more
>>>>>>>> benefit than cost here.
>>>>>>>
>>>>>>> Would it make sense to discuss that at LSF/MM once again, especiall=
y
>>>>>>> covering why proposed alternatives did not work out? LSF/MM is not =
"too far"
>>>>>>> away (May).
>>>>>>>
>>>>>>> I recall that the last LSF/MM session on this topic was a bit unfor=
tunate
>>>>>>> (IMHO not as productive as it could have been). Maybe we can finall=
y reach a
>>>>>>> consensus on this.
>>>>>>
>>>>>> I'd rather not delay for more bikeshedding. Before agreeing to LSF I=
'd
>>>>>> need to see a serious proposl - what we had at the last LSF was peop=
le
>>>>>> jumping in with half baked alternative proposals that very much hadn=
't
>>>>>> been thought through, and I see no need to repeat that.
>>>>>>
>>>>>> Like I mentioned, there's other work gated on this patchset; if peop=
le
>>>>>> want to hold this up for more discussion they better be putting fort=
h
>>>>>> something to discuss.
>>>>>
>>>>> I'm thinking of ways on how to achieve Michal's request: "as long as
>>>>> there is a wider agreement from the MM community". If we can achieve
>>>>> that without LSF, great! (a bi-weekly MM meeting might also be an opt=
ion)
>>>>
>>>> There will be a maintenance burden even with the cleanest proposed
>>>> approach.
>>>
>>> Yes.
>>>
>>>> We worked hard to make the patchset as clean as possible and
>>>> if benefits still don't outweigh the maintenance cost then we should
>>>> probably stop trying.
>>>
>>> Indeed.
>>>
>>>> At LSF/MM I would rather discuss functonal
>>>> issues/requirements/improvements than alternative approaches to
>>>> instrument allocators.
>>>> I'm happy to arrange a separate meeting with MM folks if that would
>>>> help to progress on the cost/benefit decision.
>>> Note that I am only proposing ways forward.
>>>
>>> If you think you can easily achieve what Michal requested without all t=
hat,
>>> good.
>>
>> He requested something?
>=20
> Yes, a cleaner instrumentation. Unfortunately the cleanest one is not
> possible until the compiler feature is developed and deployed. And it
> still would require changes to the headers, so don't think it's worth
> delaying the feature for years.
>=20

I was talking about this: "I can live with all the downsides of the=20
proposed implementationas long as there is a wider agreement from the MM=20
community as this is where the maintenance cost will be payed. So far I=20
have not seen (m)any acks by MM developers".

I certainly cannot be motivated at this point to review and ack this,=20
unfortunately too much negative energy around here.

--=20
Cheers,

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/a9b0440b-844e-4e45-a546-315d53322aad%40redhat.com.
