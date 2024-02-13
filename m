Return-Path: <kasan-dev+bncBC32535MUICBB2HHV6XAMGQEATDCPNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id A3B03853F41
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 23:57:45 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-dcbee93a3e1sf2857872276.3
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 14:57:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707865064; cv=pass;
        d=google.com; s=arc-20160816;
        b=KDF6n4oNV/8a5rlxXVUe5taKXtgDhiwV3rQx/nZqIxUGc2OpUaDG5RLxybVFVwUdrX
         ueC1LTLHsxEVFP8j6s5QDfR1vbVpdpW6NNFCHiMFLePJUZIQiYSUAQ0HSFcQfdG+0QwV
         347gjWocxvAmYURLu7tuPm3q6hNK7pZhSai0Or54O4x9bp3E8q564BA1+3yy3HESupfp
         /AAGwyt2NecZ1HqaHGmTMtPEM2X0jyWUfPrY+u1I6yv0UKq4A5nH1tR5cVU+v/wfKFm+
         4c9mdRrOyMEvgLuaR6sMnVgh31KScWD6/+0EGfOaB5RM6vnOJAu4zNxZpbiJUiT5cU28
         9K8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:organization:autocrypt:from:references
         :cc:to:subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=gtzWpZUJraG2Qm6+yKAVqXwDq8rX8XiSO7A7Mo4qHQs=;
        fh=E4dszjb4/BR9pXvf3gyugCHpYqZa0Y4WzqSoQz8CDkc=;
        b=SHnh/wk4Xcjs+NQYhVd2gH9j5PslcbR8hiBkQ21w5ml63FmYRdt3WXWhaQTGMGVDJu
         XZAKDFESTz6yCWw6er1nt7mTIgbPjIE7dmy3USCDc18fjfZgnJM5yj0H/iw04Pm3g23U
         VY5mzBQdRUAW2S33tZc71MLFT19hxJ7rVWDyHZJTsjtibbaCN4INF0cqz8w7wyNebSfl
         cORloG5NBKMubIcuqkRwbRU4h9EvM2Cm2x4Tz6+Th1Dumpli1gfzDxQ71tgqDo+8SEx6
         rYO7558lDoC0S63+13vtLgAWclDl4BioK9LyiTGhdmVNBvp0U+Fw9/Rk7gHq6K3nPNYW
         cWDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=FOKGqARn;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707865064; x=1708469864; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:organization:autocrypt:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=gtzWpZUJraG2Qm6+yKAVqXwDq8rX8XiSO7A7Mo4qHQs=;
        b=xowHNvDL7wFQe1ENbWBgMhMhCvClYfR4mMYsbvCys2flIgTALRVYIFx1yGcjNxOzK2
         V0iVJQnAfbTzPNQSmn+5qVBveNEklTwXIGA8wGaxFFdjVsHL4InhZwhjyQWvDZfQNR4k
         JWIWlAh7hC0r5ODd+dpCrl8NrkxGDBRnFQNHGNo2fik66yJ6fLRN4EeDrEEcu8QlCSuq
         dqYMQUKAlKdSymCLo4C85OMy0psYpcQ3TeLAntGWK1rdohRjwBzxAH8mBJ8m87ef+VYG
         0uwn5phrGt+eB6vZrAmFnXm/Gpf48JKkwIX8zQUxPT5v0l63CslJMQOhmtgiloRnkeC3
         Qwyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707865064; x=1708469864;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gtzWpZUJraG2Qm6+yKAVqXwDq8rX8XiSO7A7Mo4qHQs=;
        b=XdO+tLWhJlRVJajHNt1TwP7EqomuV9u0yaJAPaW9FgfyifmbPGYXtZkbkvP5uVOPrW
         GHDj1BQ6qfthOMTo+OcSh8514jB4RRDbtDSh43qhsJE/oHjM1SAU2ZKaWbzozehfk7E4
         4XgsXhH9bBpi6oeHRoLxUJCkO/J9cphzcVrTDc84SDARnSsaQAG3VVO+1SB65RimnClu
         M8vO63oBigDY6+DDi+PLW0UIhcmXI+nQMTNkqOPL/qKF1XwPnQO1QcDmhJ21VWbR9se2
         CFpveRfvpK8xAIRa28DSsnBZ3DegR9660+lU/KXVJbHs70IrA64RY9stPmsWXUYXRYvv
         TJWA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUrp3GJZblWAMDD9cdOwmyGZfB56o9PSOFVn5yI0RES+vmjZM1fkhbxHSw+d8OSG+IwvhI9MYfBJZXaMZ9CkK7P5MjBuz/9Xg==
X-Gm-Message-State: AOJu0YzX44ymlDspTmsLIFTcJqBU5QDZ1atePvWhtSe00geUk9YKHB+A
	yo1Pwoq/wBrBrDH/9n8L4RHNBrLec25o/jnknmPrqKQLVsNYVyyx
X-Google-Smtp-Source: AGHT+IH7WTmaERN/wQ5DFMO8YTDzhQzGZnVyJgxiq8yNsFIZrcKSAjgXKHacq7tu43GHOjIAYYm56Q==
X-Received: by 2002:a25:ae5c:0:b0:dc7:3265:37a9 with SMTP id g28-20020a25ae5c000000b00dc7326537a9mr786008ybe.37.1707865064351;
        Tue, 13 Feb 2024 14:57:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:e0c5:0:b0:dc7:4417:ec4e with SMTP id x188-20020a25e0c5000000b00dc74417ec4els142366ybg.1.-pod-prod-04-us;
 Tue, 13 Feb 2024 14:57:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVLH8Mh9fgcBRgSRyzTJ1waXopPO+gF5+Y8tixKsu8UF46hMR52nJTQdeCQ/MOseNTcqqvxvbqWltsmBNR1gLKzdQuurp2YFf0QYg==
X-Received: by 2002:a25:9343:0:b0:dcc:f5d4:8b44 with SMTP id g3-20020a259343000000b00dccf5d48b44mr815632ybo.1.1707865063528;
        Tue, 13 Feb 2024 14:57:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707865063; cv=none;
        d=google.com; s=arc-20160816;
        b=k9tCPsryzzrzVjGt+hBPBMWRmnN/GFO2mj/VFLQIjq929sq3xv30u6gtqaK2efx6pR
         AUz81t796MZm0Kijg589bqcEqb8F9VJGhG2zhTpOxRpfUPLGFdWSAZdaUY32Y2weq3R9
         qcUzcNidUH6X7qhoUcBenhqIyzdS6Vt5+sRPXBLFKSPQceCUWOd/8mn8fu9RkAc66vFy
         k9T8m3aVbJbeANGPHJ+euHlg68aHZOfskNaLXX6IPOtemMiqY5oop4ahSHw1cMdY668P
         3LTpu17kxxBVMu2Jq+VBKgGOhMVm5mwOo+kMiY8BzOhqqacN1xrz1GD+nK/Y2eUN6fkK
         P9/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :autocrypt:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=46CJF8ki9aog8H1XgwfThvnTA8WcsAcCcWmi4TUP1b0=;
        fh=2PGlMw+MfwMrB+V3W8hl7i6yOpqc+UO6twIlC8XkiPk=;
        b=LVCnpsC+ESQpoDRiHmamajqfto89o1pv04XhOC+fhhcQikpawMnuRquNSHHX1MhDwW
         lsbc5T0+GkCZTAhAx4tlosbxV3QSg//x6juZsoeTsmTHwkgK1sRvss+IyCbcuhTvvGdf
         f7MXFSrPMZy7tM3lY3J0agFkN8G0bDf1PneJ5w77CjlO2Pi2P7LAg8qyfVRvBN1yDzTD
         U++ymtrEDSFRG2mDdN4m2PsZTnbnjDIwbppH2lJ3csvQ9h9nubvSU50oL76y+opbnBTI
         1rWoHzz3+NeN55T6N3tfLtOlAYqH2sca3YjEZh1zf66gEuApX5N7oKqu2aNv+CkOqylZ
         7q3w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=FOKGqARn;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
X-Forwarded-Encrypted: i=1; AJvYcCUGIOdxyOh98Z6XUbdZTIZ8Umrs178QNRfA4xlhSvXhTEUyutnd5rF2ZZiLsadLIAYbFE0APEs7bFJBjqlILh0OmGR8/dLHuHjVqw==
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id p77-20020a25d850000000b00dc657e7de95si366995ybg.0.2024.02.13.14.57.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Feb 2024 14:57:43 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-qk1-f199.google.com (mail-qk1-f199.google.com
 [209.85.222.199]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-119--6QmL7HsNdKpPIEU40BCLg-1; Tue, 13 Feb 2024 17:57:41 -0500
X-MC-Unique: -6QmL7HsNdKpPIEU40BCLg-1
Received: by mail-qk1-f199.google.com with SMTP id af79cd13be357-7817253831cso653628585a.0
        for <kasan-dev@googlegroups.com>; Tue, 13 Feb 2024 14:57:41 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWMGRPudUqhBirqkiJqNg5S2WqalYfkeAZ1AaOgji6qWE1qxeCp3XR9yUQEM17iaUQafCD77FOO7S2YVPxrF0N4lIBpYeiNf5/PZw==
X-Received: by 2002:a05:620a:15aa:b0:785:c4ee:7903 with SMTP id f10-20020a05620a15aa00b00785c4ee7903mr1041468qkk.57.1707865061171;
        Tue, 13 Feb 2024 14:57:41 -0800 (PST)
X-Received: by 2002:a05:620a:15aa:b0:785:c4ee:7903 with SMTP id f10-20020a05620a15aa00b00785c4ee7903mr1041388qkk.57.1707865060779;
        Tue, 13 Feb 2024 14:57:40 -0800 (PST)
X-Forwarded-Encrypted: i=1; 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
Received: from ?IPV6:2003:d8:2f3c:3f00:7177:eb0c:d3d2:4b0e? (p200300d82f3c3f007177eb0cd3d24b0e.dip0.t-ipconnect.de. [2003:d8:2f3c:3f00:7177:eb0c:d3d2:4b0e])
        by smtp.gmail.com with ESMTPSA id h14-20020a05620a10ae00b007872ade6cf1sm5569qkk.71.2024.02.13.14.57.31
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Feb 2024 14:57:40 -0800 (PST)
Message-ID: <22faab25-9509-483f-b9e9-d810de1f639f@redhat.com>
Date: Tue, 13 Feb 2024 23:57:29 +0100
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
 <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com>
 <CAJuCfpEtOhzL65eMDk2W5SchcquN9hMCcbfD50a-FgtPgxh4Fw@mail.gmail.com>
 <adbb77ee-1662-4d24-bcbf-d74c29bc5083@redhat.com>
 <r6cmbcmalryodbnlkmuj2fjnausbcysmolikjguqvdwkngeztq@45lbvxjavwb3>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; keydata=
 xsFNBFXLn5EBEAC+zYvAFJxCBY9Tr1xZgcESmxVNI/0ffzE/ZQOiHJl6mGkmA1R7/uUpiCjJ
 dBrn+lhhOYjjNefFQou6478faXE6o2AhmebqT4KiQoUQFV4R7y1KMEKoSyy8hQaK1umALTdL
 QZLQMzNE74ap+GDK0wnacPQFpcG1AE9RMq3aeErY5tujekBS32jfC/7AnH7I0v1v1TbbK3Gp
 XNeiN4QroO+5qaSr0ID2sz5jtBLRb15RMre27E1ImpaIv2Jw8NJgW0k/D1RyKCwaTsgRdwuK
 Kx/Y91XuSBdz0uOyU/S8kM1+ag0wvsGlpBVxRR/xw/E8M7TEwuCZQArqqTCmkG6HGcXFT0V9
 PXFNNgV5jXMQRwU0O/ztJIQqsE5LsUomE//bLwzj9IVsaQpKDqW6TAPjcdBDPLHvriq7kGjt
 WhVhdl0qEYB8lkBEU7V2Yb+SYhmhpDrti9Fq1EsmhiHSkxJcGREoMK/63r9WLZYI3+4W2rAc
 UucZa4OT27U5ZISjNg3Ev0rxU5UH2/pT4wJCfxwocmqaRr6UYmrtZmND89X0KigoFD/XSeVv
 jwBRNjPAubK9/k5NoRrYqztM9W6sJqrH8+UWZ1Idd/DdmogJh0gNC0+N42Za9yBRURfIdKSb
 B3JfpUqcWwE7vUaYrHG1nw54pLUoPG6sAA7Mehl3nd4pZUALHwARAQABzSREYXZpZCBIaWxk
 ZW5icmFuZCA8ZGF2aWRAcmVkaGF0LmNvbT7CwZgEEwEIAEICGwMGCwkIBwMCBhUIAgkKCwQW
 AgMBAh4BAheAAhkBFiEEG9nKrXNcTDpGDfzKTd4Q9wD/g1oFAl8Ox4kFCRKpKXgACgkQTd4Q
 9wD/g1oHcA//a6Tj7SBNjFNM1iNhWUo1lxAja0lpSodSnB2g4FCZ4R61SBR4l/psBL73xktp
 rDHrx4aSpwkRP6Epu6mLvhlfjmkRG4OynJ5HG1gfv7RJJfnUdUM1z5kdS8JBrOhMJS2c/gPf
 wv1TGRq2XdMPnfY2o0CxRqpcLkx4vBODvJGl2mQyJF/gPepdDfcT8/PY9BJ7FL6Hrq1gnAo4
 3Iv9qV0JiT2wmZciNyYQhmA1V6dyTRiQ4YAc31zOo2IM+xisPzeSHgw3ONY/XhYvfZ9r7W1l
 pNQdc2G+o4Di9NPFHQQhDw3YTRR1opJaTlRDzxYxzU6ZnUUBghxt9cwUWTpfCktkMZiPSDGd
 KgQBjnweV2jw9UOTxjb4LXqDjmSNkjDdQUOU69jGMUXgihvo4zhYcMX8F5gWdRtMR7DzW/YE
 BgVcyxNkMIXoY1aYj6npHYiNQesQlqjU6azjbH70/SXKM5tNRplgW8TNprMDuntdvV9wNkFs
 9TyM02V5aWxFfI42+aivc4KEw69SE9KXwC7FSf5wXzuTot97N9Phj/Z3+jx443jo2NR34XgF
 89cct7wJMjOF7bBefo0fPPZQuIma0Zym71cP61OP/i11ahNye6HGKfxGCOcs5wW9kRQEk8P9
 M/k2wt3mt/fCQnuP/mWutNPt95w9wSsUyATLmtNrwccz63XOwU0EVcufkQEQAOfX3n0g0fZz
 Bgm/S2zF/kxQKCEKP8ID+Vz8sy2GpDvveBq4H2Y34XWsT1zLJdvqPI4af4ZSMxuerWjXbVWb
 T6d4odQIG0fKx4F8NccDqbgHeZRNajXeeJ3R7gAzvWvQNLz4piHrO/B4tf8svmRBL0ZB5P5A
 2uhdwLU3NZuK22zpNn4is87BPWF8HhY0L5fafgDMOqnf4guJVJPYNPhUFzXUbPqOKOkL8ojk
 CXxkOFHAbjstSK5Ca3fKquY3rdX3DNo+EL7FvAiw1mUtS+5GeYE+RMnDCsVFm/C7kY8c2d0G
 NWkB9pJM5+mnIoFNxy7YBcldYATVeOHoY4LyaUWNnAvFYWp08dHWfZo9WCiJMuTfgtH9tc75
 7QanMVdPt6fDK8UUXIBLQ2TWr/sQKE9xtFuEmoQGlE1l6bGaDnnMLcYu+Asp3kDT0w4zYGsx
 5r6XQVRH4+5N6eHZiaeYtFOujp5n+pjBaQK7wUUjDilPQ5QMzIuCL4YjVoylWiBNknvQWBXS
 lQCWmavOT9sttGQXdPCC5ynI+1ymZC1ORZKANLnRAb0NH/UCzcsstw2TAkFnMEbo9Zu9w7Kv
 AxBQXWeXhJI9XQssfrf4Gusdqx8nPEpfOqCtbbwJMATbHyqLt7/oz/5deGuwxgb65pWIzufa
 N7eop7uh+6bezi+rugUI+w6DABEBAAHCwXwEGAEIACYCGwwWIQQb2cqtc1xMOkYN/MpN3hD3
 AP+DWgUCXw7HsgUJEqkpoQAKCRBN3hD3AP+DWrrpD/4qS3dyVRxDcDHIlmguXjC1Q5tZTwNB
 boaBTPHSy/Nksu0eY7x6HfQJ3xajVH32Ms6t1trDQmPx2iP5+7iDsb7OKAb5eOS8h+BEBDeq
 3ecsQDv0fFJOA9ag5O3LLNk+3x3q7e0uo06XMaY7UHS341ozXUUI7wC7iKfoUTv03iO9El5f
 XpNMx/YrIMduZ2+nd9Di7o5+KIwlb2mAB9sTNHdMrXesX8eBL6T9b+MZJk+mZuPxKNVfEQMQ
 a5SxUEADIPQTPNvBewdeI80yeOCrN+Zzwy/Mrx9EPeu59Y5vSJOx/z6OUImD/GhX7Xvkt3kq
 Er5KTrJz3++B6SH9pum9PuoE/k+nntJkNMmQpR4MCBaV/J9gIOPGodDKnjdng+mXliF3Ptu6
 3oxc2RCyGzTlxyMwuc2U5Q7KtUNTdDe8T0uE+9b8BLMVQDDfJjqY0VVqSUwImzTDLX9S4g/8
 kC4HRcclk8hpyhY2jKGluZO0awwTIMgVEzmTyBphDg/Gx7dZU1Xf8HFuE+UZ5UDHDTnwgv7E
 th6RC9+WrhDNspZ9fJjKWRbveQgUFCpe1sa77LAw+XFrKmBHXp9ZVIe90RMe2tRL06BGiRZr
 jPrnvUsUUsjRoRNJjKKA/REq+sAnhkNPPZ/NNMjaZ5b8Tovi8C0tmxiCHaQYqj7G2rgnT0kt
 WNyWQQ==
Organization: Red Hat
In-Reply-To: <r6cmbcmalryodbnlkmuj2fjnausbcysmolikjguqvdwkngeztq@45lbvxjavwb3>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=FOKGqARn;
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

On 13.02.24 23:50, Kent Overstreet wrote:
> On Tue, Feb 13, 2024 at 11:48:41PM +0100, David Hildenbrand wrote:
>> On 13.02.24 23:30, Suren Baghdasaryan wrote:
>>> On Tue, Feb 13, 2024 at 2:17=E2=80=AFPM David Hildenbrand <david@redhat=
.com> wrote:
>>>>
>>>> On 13.02.24 23:09, Kent Overstreet wrote:
>>>>> On Tue, Feb 13, 2024 at 11:04:58PM +0100, David Hildenbrand wrote:
>>>>>> On 13.02.24 22:58, Suren Baghdasaryan wrote:
>>>>>>> On Tue, Feb 13, 2024 at 4:24=E2=80=AFAM Michal Hocko <mhocko@suse.c=
om> wrote:
>>>>>>>>
>>>>>>>> On Mon 12-02-24 13:38:46, Suren Baghdasaryan wrote:
>>>>>>>> [...]
>>>>>>>>> We're aiming to get this in the next merge window, for 6.9. The f=
eedback
>>>>>>>>> we've gotten has been that even out of tree this patchset has alr=
eady
>>>>>>>>> been useful, and there's a significant amount of other work gated=
 on the
>>>>>>>>> code tagging functionality included in this patchset [2].
>>>>>>>>
>>>>>>>> I suspect it will not come as a surprise that I really dislike the
>>>>>>>> implementation proposed here. I will not repeat my arguments, I ha=
ve
>>>>>>>> done so on several occasions already.
>>>>>>>>
>>>>>>>> Anyway, I didn't go as far as to nak it even though I _strongly_ b=
elieve
>>>>>>>> this debugging feature will add a maintenance overhead for a very =
long
>>>>>>>> time. I can live with all the downsides of the proposed implementa=
tion
>>>>>>>> _as long as_ there is a wider agreement from the MM community as t=
his is
>>>>>>>> where the maintenance cost will be payed. So far I have not seen (=
m)any
>>>>>>>> acks by MM developers so aiming into the next merge window is more=
 than
>>>>>>>> little rushed.
>>>>>>>
>>>>>>> We tried other previously proposed approaches and all have their
>>>>>>> downsides without making maintenance much easier. Your position is
>>>>>>> understandable and I think it's fair. Let's see if others see more
>>>>>>> benefit than cost here.
>>>>>>
>>>>>> Would it make sense to discuss that at LSF/MM once again, especially
>>>>>> covering why proposed alternatives did not work out? LSF/MM is not "=
too far"
>>>>>> away (May).
>>>>>>
>>>>>> I recall that the last LSF/MM session on this topic was a bit unfort=
unate
>>>>>> (IMHO not as productive as it could have been). Maybe we can finally=
 reach a
>>>>>> consensus on this.
>>>>>
>>>>> I'd rather not delay for more bikeshedding. Before agreeing to LSF I'=
d
>>>>> need to see a serious proposl - what we had at the last LSF was peopl=
e
>>>>> jumping in with half baked alternative proposals that very much hadn'=
t
>>>>> been thought through, and I see no need to repeat that.
>>>>>
>>>>> Like I mentioned, there's other work gated on this patchset; if peopl=
e
>>>>> want to hold this up for more discussion they better be putting forth
>>>>> something to discuss.
>>>>
>>>> I'm thinking of ways on how to achieve Michal's request: "as long as
>>>> there is a wider agreement from the MM community". If we can achieve
>>>> that without LSF, great! (a bi-weekly MM meeting might also be an opti=
on)
>>>
>>> There will be a maintenance burden even with the cleanest proposed
>>> approach.
>>
>> Yes.
>>
>>> We worked hard to make the patchset as clean as possible and
>>> if benefits still don't outweigh the maintenance cost then we should
>>> probably stop trying.
>>
>> Indeed.
>>
>>> At LSF/MM I would rather discuss functonal
>>> issues/requirements/improvements than alternative approaches to
>>> instrument allocators.
>>> I'm happy to arrange a separate meeting with MM folks if that would
>>> help to progress on the cost/benefit decision.
>> Note that I am only proposing ways forward.
>>
>> If you think you can easily achieve what Michal requested without all th=
at,
>> good.
>=20
> He requested something?
>=20

This won't get merged without acks from MM people.

--=20
Cheers,

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/22faab25-9509-483f-b9e9-d810de1f639f%40redhat.com.
