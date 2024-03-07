Return-Path: <kasan-dev+bncBDV2D5O34IDRBT6SVCXQMGQEIJYQDFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1ACE68758D9
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Mar 2024 21:53:38 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-29b99a884f5sf294409a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Mar 2024 12:53:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709844816; cv=pass;
        d=google.com; s=arc-20160816;
        b=DhogjYxfVA3lefzp1yszTP9AmirVObFBzcKnm9tXdgmJoYUWkpbXAPORfGP1OLNeSW
         BYv7IPnw8/TIK45kG3L8H2KMNFgqAOpKed1P1TozW5OL2UTxokzGEV7zVG454HMfQRfd
         Z/arV2zsdAVg2708Ze8d4f9pqgPdnBwZouyzrzzJ+x/Zff3igevh2bSqWLq+RiG7yJ/2
         tOg4OhvthTENYumxCVZ8+LNx/08SvmRSq9tg9BvAC0HJw0DRozzh4ph1OFCCYfkGTV0v
         T3gM52JhkMQgoFuVEK4kZS5Icy2qV7sViw0UoAQ1EwDIecVKGa2/RXPke//YrqZbt5vB
         T0lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=JyGfwYf+gWMUswjn517poyM5B2UGUJQvX82RXJ3QLQ0=;
        fh=xAP9KzD1FDO0qFev75PJpibWyXVvFEkjUsIPhbNdhUo=;
        b=j4wyrJonYCV3AIVIDHs94/b5RUrWmghwyGRhCV/Tv8KtUIzGpJ5HP0g0VelYAE0LKP
         aEXCTKWiBXUpEN3jCGcT/evp89g2LqMpXD1mJMOn4ED+pbycYmyABry0xLssdJKh8ghx
         umoGn8AeKhSIICJMVDwnl5qT0LAFXjQYroK5VajyCfwr0JAXCgU7O3GkFvjsymncxQy/
         S088JqsKSgUFsIklneGNW99JcEl9uMt5J1TAe8oZ3jELVVqbuqNQWp9K4fuhATQKZ211
         zEk8OxDW98HKU3w6M+wlu6gdOxcfrZotSxH7hcZiHcc8+EODCGSbPCsd0S352N0V2NbL
         DWQA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b="TOvuaa/3";
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709844816; x=1710449616; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JyGfwYf+gWMUswjn517poyM5B2UGUJQvX82RXJ3QLQ0=;
        b=FK65dUWoMfWjFwFrZzmyCtlV+7XpaFEdhIDCefYr1zBLM9dT+MV/Mz9isk99pFzLCg
         LPB3/z7r3RpjrqgMBFTdReeZLLQiK9w6o3vjOTU4RaX2P41oEhpzgj5Gjan04w2P8WWr
         qYr2tnZwx0e9ffBuoxh1eM7Tm+GOdJd4je3kQekfjkVP0fagqw2QinashX0nYU4GYb6Z
         A0ks3i6Gb2b/hCtm/0vRc2mD1mTGU9FFJ1JgWd73XY8GZ4178hykKvx27KrMrBfSZBjH
         oIMX8UX4ti5cz+VbVAjN1gAJbHBNFkhfaNv/dWS70dDyodsnzRktm4a1EfktBpQbtExr
         li/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709844816; x=1710449616;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JyGfwYf+gWMUswjn517poyM5B2UGUJQvX82RXJ3QLQ0=;
        b=PzWzDDcGAe8GQXxuVWCrrarekEeEy48rvJq54K2cudxmAdfNagq1Vzvp6hWTFCtmme
         9D+CD7o+dvVWyoGQ1TOdUuqiK1crdgtKpWScJUsj7E9nx8M3iPuYV6q+jpkSXXHjQgP5
         +0NZYAa3KVcE5UvMyBzu6PQKcFUcSCyh37AwPxkWKHCVl/9tl/FEhnNzjSKbnrpMcZf7
         8+/bw1iTM5BZ43uAJqxbds91AAmr1vhBXq+2LJXiGn0sgYIRH3secyKA4njPNLeCcgyW
         6TN8QDtn3n0kciH7oeLIFunn2z1rsysBSAo2MrFdV+oX8LAsE51cfoKSLHjGVzhDFwzx
         onKg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWMpnWbz2hzllYNKb/PP/Gni4W0Bd/j2C4q3raF5jUAK/gB/64pkgWK3iGtn+Ws1cjMyKd7J3w3AdvVwCqwHPyAa1+ozs0DLw==
X-Gm-Message-State: AOJu0Yx9iC6+h6j+N6UpovOGY8cx6njXsOcrfCaSy2Ljg32DDBgM/zdA
	vnJldi5QKoWZMUsUuyr4j1NYDxii3ruYYKGcemXDOLuv8ZOyXhy2
X-Google-Smtp-Source: AGHT+IGfkvhDqdqG7Txrp3E2fY+gq2WYGnA2k6MVxmh2ztmp/PBVV/WSfS4xPlbwdGOIsbwP2BdDtQ==
X-Received: by 2002:a05:6a21:3381:b0:1a1:4534:bc45 with SMTP id yy1-20020a056a21338100b001a14534bc45mr53987pzb.6.1709844815917;
        Thu, 07 Mar 2024 12:53:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:98d:b0:6e6:6a7c:1924 with SMTP id
 u13-20020a056a00098d00b006e66a7c1924ls60877pfg.1.-pod-prod-08-us; Thu, 07 Mar
 2024 12:53:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVyvYzkmUYA9FKVMAuVwuCbtpenOtEYzoGFi/1hESffic7uyDmpmVMcdteir/n0pIW4e9Zfox9DDx+TtYcsXZEIcJvpLzbM03pCPw==
X-Received: by 2002:aa7:88c7:0:b0:6e5:5a22:10ff with SMTP id k7-20020aa788c7000000b006e55a2210ffmr22371083pff.2.1709844814766;
        Thu, 07 Mar 2024 12:53:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709844814; cv=none;
        d=google.com; s=arc-20160816;
        b=k38ia4wwVpZwJRG07rGUv9EjqkudDZsWY2hqG0faVVBq7FeV2RxWBc4MRoh8or5FgE
         QTkIJPisAAK3lrXH/nXITFXIklOvdCzVXM0tuED51tv3uEAKQhHSYBid/PInfoZcLOl7
         T7+QA5A4ek0rDaxsZt0JGx2+Z/6RIxXzgFw3ltJ8RX4XcyweJCZyYutbe/QTrHMTwgcQ
         csMr6SKEZGGDgWA9NaLoNd78m1qzq3JKWyDpubAjqs5fxoW4EFq41JdHTrtYN9HGsWxO
         sL3MdPZCwIeACovqRBYUQwcGawHILCvtRRWpOWhHDoJvhm595SE3b3U5MVrv+qeCLtZa
         9Iig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=p08jq4TIBI4zazg51JnXnjGH5Lu+du6lZuf9B2Rz4QQ=;
        fh=KeKjdBYjXjK8l7xav2yskcnLinQuS7RNyfhs6suydGc=;
        b=I7QM35IgVvWLB3mYY2wSLOQl0nX+YS7PEwd4nncUcwINWJbYZfKqNC0HiCkPvgGcSv
         fvy879BlBXSmgBeirUodkUs3yehO+w4lggyATFWACsqOgSF8I3n9dRyK63QcUVweDz4T
         bqPllObO6Mc5ZF1UVnQaiVOq2+xEuil70xM+QGpZYtTLxEiiumc28IAV5l1+pOokSrPJ
         inqoWvRTDB55bDY840oYKP+L/LHnFr/svBgyJho+HXdl19HCbYkVTXshOX9ukb2oQZtW
         99v+B5h2jnDMOBoII/tD/2cL2OopUv4arMLdZe4p1E0PbRNW1BHx0AWJ1yrD3dKQUX/X
         NGPA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b="TOvuaa/3";
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id y38-20020a631826000000b005dc13d8277dsi1533068pgl.2.2024.03.07.12.53.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Mar 2024 12:53:34 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [50.53.50.0] (helo=[192.168.254.15])
	by bombadil.infradead.org with esmtpsa (Exim 4.97.1 #2 (Red Hat Linux))
	id 1riKjl-00000006Lv6-1biU;
	Thu, 07 Mar 2024 20:53:09 +0000
Message-ID: <25a03dba-8d6b-4072-beae-7ea477fccbcb@infradead.org>
Date: Thu, 7 Mar 2024 12:53:06 -0800
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 37/37] memprofiling: Documentation
Content-Language: en-US
To: John Hubbard <jhubbard@nvidia.com>,
 Kent Overstreet <kent.overstreet@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
 mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com,
 penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
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
 <hsyclfp3ketwzkebjjrucpb56gmalixdgl6uld3oym3rvssyar@fmjlbpdkrczv>
 <f12e83ef-5881-4df8-87ae-86f8ca5a6ab4@infradead.org>
 <72bbe76c-fcf9-47c2-b583-63d5ad77b3c3@nvidia.com>
From: Randy Dunlap <rdunlap@infradead.org>
In-Reply-To: <72bbe76c-fcf9-47c2-b583-63d5ad77b3c3@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b="TOvuaa/3";
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



On 3/7/24 12:15, John Hubbard wrote:
> On 3/7/24 12:03, Randy Dunlap wrote:
>> On 3/7/24 10:17, Kent Overstreet wrote:
>>> On Wed, Mar 06, 2024 at 07:18:57PM -0800, Randy Dunlap wrote:
> ...
>>>>> +- i.e. iterating over them to print them in debugfs/procfs.
>>>>
>>>> =C2=A0=C2=A0 i.e., iterating
>>>
>>> i.e. latin id est, that is: grammatically my version is fine
>>>
>>
>> Some of my web search hits say that a comma is required after "i.e.".
>> At least one of them says that it is optional.
>> And one says that it is not required in British English.
>>
>> But writing it with "that is":
>>
>>
>> hence code tagging) and then finding and operating on them at runtime
>> - that is iterating over them to print them in debugfs/procfs.
>>
>> is not good IMO. But it's your document.
>>
>=20
> Technical writing often benefits from a small amount redundancy. Short
> sentences and repetition of terms are helpful to most readers. And this
> also stays out of the more advanced grammatical constructs, as a side
> effect.
>=20
> So, for example, something *approximately* like this, see what you
> think:
>=20
> Memory allocation profiling is based upon code tagging. Code tagging is
> a library for declaring static structs (typically by associating a file
> and line number with a descriptive string), and then finding and
> operating on those structs at runtime. Memory allocation profiling's
> runtime operation is simply: print the structs via debugfs/procfs.

Works for me.  Thanks.

--=20
#Randy

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/25a03dba-8d6b-4072-beae-7ea477fccbcb%40infradead.org.
