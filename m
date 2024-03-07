Return-Path: <kasan-dev+bncBDV2D5O34IDRBGFZVCXQMGQELJO4DEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 841B18757BF
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Mar 2024 20:59:22 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-36541324e57sf10797865ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Mar 2024 11:59:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709841561; cv=pass;
        d=google.com; s=arc-20160816;
        b=zmZRj68cAvLe3zI7L+YZkKAHDdFMdPQG0d1SpJtLjXkzIx1Csl6rsqowfFHYlVvgVl
         naauiEWcRMjrQJvb1DFdqfMxcru4qbK5Rv+Z4E15GGv5tuspF6X2zhXwzwM5hhYovj/c
         iMY1B5H2abWrPEKUBpLUyopAtGZr1dULVv39EtBPIVK4qNs74nbmI7aarRpin/omcCAB
         FwzGmKAtGJYXkBTQLy8RekAAGkFb1RKdkGgacOtFXrqhd7YC/J8RgKi88P7qgJveIn6n
         vKlWA/38a4zraQDKF02qGY+BHkmkTnWE3X4qR3Fg7XrywlRoITTHXrMvljSFrGAqnmVt
         UGXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=fcp7RQGVfifItvnrL2hHtlaj/3dpdSiKLmgdbzOK4NM=;
        fh=fKS0TCCX542W/weWVyU+CN+1SZsUNCefbPbY2bgsHjY=;
        b=K33gxqMvAloiQhS8Rn7ni4HKS7+Fhmo0gIPMO0Zgq8fFGiBUEV9KNuT43NOOSCu9H7
         bdkt3CG3d5Q6Xu0nYLrf+M0GU6XzFvPhNg9e43Uy6TObaBLCFYrHFaSy2xuS784DPKpW
         WB2HE0c1VKEx3ja4tKF3deE5Xm9y3RbpL83JQlmdIooa+y+KVcWwK/u/bOM5Q2UIreE1
         R45RJuOLDAUP1DgOPV8pXHAVv3wv1y+QFdik1ZTC1dgyeexx9DbkDHO5fAtJI8N+UcN0
         y9lJUTBZyG5vgFRL7DkSjY04AMFERmEoX+5SetoXiM62bPFgqHSq0U6b/+8YuB1tbAo0
         fPuA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=f3WrWocD;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709841561; x=1710446361; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=fcp7RQGVfifItvnrL2hHtlaj/3dpdSiKLmgdbzOK4NM=;
        b=ECkxnticyswzTm+YQW8G98+5aWhA2Q14TAngB8UDFuquK8yhNOtr1VA5bcK5hlYjnn
         ShvKYv6tyOk9fD5d08HKBZwa0iC6ZL8wvv7uIqcQuhx+coWsSq80BgnhlTXvZCtcNrgn
         gP5JKIJLCBMaeYeKYdcI2hfrW0rbGSlTIWascpC7zVgynNC7x++aunTpRXnwARBL8PHf
         yy5nKclu6F0rC24ZTICiMyctdvdyxMZDzuHa0XiqpwF5m7V78A1cFqVSJtAXM8rDRL3j
         m6WpsZI0ZL2nYh9G1j+DF0H5nzv55j2ZFicdXNbM0PKgbM0syUUdTDIhAD9YhHdEr/87
         0iNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709841561; x=1710446361;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fcp7RQGVfifItvnrL2hHtlaj/3dpdSiKLmgdbzOK4NM=;
        b=RRi5CKh6aV8NntDnjZLZeGhBgPvLJDVAHGVuCirqRMqP0ZPRfy16GHitcossc7+JxG
         i9Jy5c4ZP9UellpbKcqQIuYwuTieBlriaYd8EbbYlHV8QtENXAH+7YGHGO84KB1Lw6YE
         D/sbHPTKMBlv8gj4TwzFLgeu9miuh5mRkj15J3rLxARS3mXwmQkMy4TIwIlja5c/pIiY
         bnufy2FZrJIQDrSNR0cmOdk8Hic4gKwlQ1jcayB7fvDzH8sdsAiop978eII5lVL1tt89
         ahwWhfd3cValIShhXBl28Nw/Ct75tWytu4PIKIbGxQ1DU2DVHyeE/3BBrCZNo7N5ncBw
         5lyQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVckjzjDnHwC40/PRC+7amtJ5AZfhbMat15LqXZqA0zP2kfJM/B/hUSko4rFZMqKZY/pvDmaQJ39olPaigahW+h45dOYdEH8A==
X-Gm-Message-State: AOJu0YzUaq656EeIuVs6cqmfR5SkttbDJ5eNqju9lIT7I3zi0r+CYKx+
	ZQNNMM/SU/4fzZ7SzGJApPxgyNEbCCaVW8ak60s5i609UTO44cSi
X-Google-Smtp-Source: AGHT+IGyr+fQGKAwbONxLhSNVH1BNO4LOw27lvULtjQsrAOiBXZSOUndLzwJ5uM0mXyOpvKNyIw6rg==
X-Received: by 2002:a05:6e02:18ce:b0:365:a64c:e2be with SMTP id s14-20020a056e0218ce00b00365a64ce2bemr25822825ilu.15.1709841560646;
        Thu, 07 Mar 2024 11:59:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d05:b0:365:a664:c570 with SMTP id
 i5-20020a056e021d0500b00365a664c570ls882396ila.1.-pod-prod-02-us; Thu, 07 Mar
 2024 11:59:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWexBUlRoyIJV9OCTdNzb8WDG84hezXsGfZ419RfE3XtTw9DlsdO/T5zI36YO8XqxXJOlsZdyNUDkLIPUod3sQZU3OrIwJpvvMwEQ==
X-Received: by 2002:a05:6e02:1a8e:b0:363:e7c8:2180 with SMTP id k14-20020a056e021a8e00b00363e7c82180mr24856215ilv.12.1709841559748;
        Thu, 07 Mar 2024 11:59:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709841559; cv=none;
        d=google.com; s=arc-20160816;
        b=haI6/8MhWdeObP59JLatOpdflaf74wCI0i7XG53AEbBMi75HsdsRht3340F64M2MhR
         mk8gpa/rFEuyr9uk+V21FxmGhusLK2WDIgJNLFQxaPmQYJvaJU//F2fgld+alKfJkdOq
         fUEHEc8wv4HSEoruRbaAI3hnFizX7p7oUYwUnZ+1sokfmscnGlwLGi9mBCEbiFCFoCC2
         v7GQnV3+ZlZ4UtXjysUnU7KSOLUsfaYB79PUwHfJayc3VSJENCxYVQRB9wfOOaQbpVWH
         34VEWycWGu868q7OZL+cojTE6i/z4CXEBG0ORD6C/nIlOO0P1Yd+9YX0yO3o7CfOW4Qt
         Cefw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=KVaCyMJy+vYOeUyoSR5Mk9pa+MCPgO2uUL4D5SXL/4U=;
        fh=gXlaHLgcPdR5lDJyqVFH5ufIm2/NMewMBTVO7B2XskI=;
        b=rpxkm4Dqeb4mYX8BOG872lG38q2e3sOvCJLaWc9B0XhpZRR7a4cjBk3ZG7VQZoRUBu
         CyTNOw8FXPKvvqyyoqeWZaGbVZlfqTE8Kdr4Zd52ogB5E9jaWQMXFii69L86V7/rbf3X
         hniXJk89UH6N6vzcpM1LPkJMyqLAQSimr6QEC2zqlaUR74ZoHnQsHfxUMEsKX2nVskix
         C6xoyL/Ngl6j7QlYoc8xWdK6cCKp/5iBk6qMAMSdDHUugaIO7cjHPmd6y4ujWXDgqnS2
         kc9GAew5fBO7NvFhCOhj+Fc1WvkuD6i+i8YuvPAGC97TQJU0RozgXPc8FkjUW0FIdmFy
         D4yQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=f3WrWocD;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id c2-20020a056e020cc200b0036508ac8c22si1402102ilj.5.2024.03.07.11.59.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Mar 2024 11:59:19 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [50.53.50.0] (helo=[192.168.254.15])
	by bombadil.infradead.org with esmtpsa (Exim 4.97.1 #2 (Red Hat Linux))
	id 1riJtE-00000006Axx-2mZO;
	Thu, 07 Mar 2024 19:58:52 +0000
Message-ID: <299be3c9-4cf4-47ce-b53a-c9789af4f5ca@infradead.org>
Date: Thu, 7 Mar 2024 11:58:49 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 37/37] memprofiling: Documentation
Content-Language: en-US
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
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com,
 rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
 kernel-team@android.com, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
 linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
 linux-mm@kvack.org, linux-modules@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org
References: <20240306182440.2003814-1-surenb@google.com>
 <20240306182440.2003814-38-surenb@google.com>
 <10a95079-86e4-41bf-8e82-e387936c437d@infradead.org>
 <CAJuCfpFN3BLsFOWB0huA==LVa2pNYdnf7bT_VXgDtPuJOxvWSQ@mail.gmail.com>
From: Randy Dunlap <rdunlap@infradead.org>
In-Reply-To: <CAJuCfpFN3BLsFOWB0huA==LVa2pNYdnf7bT_VXgDtPuJOxvWSQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=f3WrWocD;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=rdunlap@infradead.org
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



On 3/7/24 08:51, Suren Baghdasaryan wrote:
> On Thu, Mar 7, 2024 at 3:19=E2=80=AFAM Randy Dunlap <rdunlap@infradead.or=
g> wrote:
>>
>> Hi,
>> This includes some editing suggestions and some doc build fixes.
>>
>>

[snip]

>>
>>
>> Finally, there are a number of documentation build warnings in this patc=
h.
>> I'm no ReST expert, but the attached patch fixes them for me.
>=20
> Thanks Randy! I'll use your cleaned-up patch in the next submission.
> Cheers,
> Suren.

Hi Suren,

The patch did not include the grammar/punctuation changes, only the
doc build changes.

I can make a more complete patch if you like.

thanks.
--=20
#Randy

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/299be3c9-4cf4-47ce-b53a-c9789af4f5ca%40infradead.org.
