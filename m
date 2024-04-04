Return-Path: <kasan-dev+bncBDV2D5O34IDRBQ5NXCYAMGQEPSRZTFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 4806F897DE8
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Apr 2024 04:56:05 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-369fcc92abdsf4632995ab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Apr 2024 19:56:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712199364; cv=pass;
        d=google.com; s=arc-20160816;
        b=oTgfg84QpsUUUjLbgZEjFancKuqksleyKM0nVCAbBpGXx65YZX/MyPZRFJvkqcs8/x
         kqIpWuVol1g2apIfO2ELr4nnu4avwfIS0/bQbM5T7xeHqCYq6VbKxAYmrluk2pHpNEtq
         pX2098TcCIU/Ezflf/yFoqleULQ5fJ85hS29fsG0tztZ0GcwV+5oxz7lqHDBs2MY0fQD
         JqtBTxbELGT1SOqSyFjw3Q188aiM8LbXBt5ezEj46uf0Vh+bU1CS0IRRs+P3+BcDpOTS
         H3DOk3cWdkMNZhykFAObTsv0MisoLnPquH4vX3qi5s0jLC33eyoxoHRed6Mh3ACoAg1V
         LEhQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=7FljA/ACLrLvEEjUg2rr5zHGT8ulqIASfAuzJFtbOx0=;
        fh=LvF7D9VzPB21GcKJOGVFey95gm2QE4xstcI8kevM/ng=;
        b=AtNqey7WsnKG9qTEjI/GoDMeaeXB6Uhe1WKrnF5K2mZ6bsPPaXCXtAPHzBH/ou1nLN
         6e0YFSi7XRWDcwaGH1sSR19hmGb5zfWpVsSkxx1W4U8BN6o6uNBDY9Ff2DZWt10GsD8p
         5EYBpQlH8/oA8nXE6P3YbnXfWRGaI0PP+dku1RFKNz5DMVkG2k0RQDbnP7FSlWuxRT/B
         kGZF2ik4+VFPleLBsFHklnCFb3+uX2REK4cJdKjxmY1FAh3JS8SBrGNprCVSiwIkUzDE
         u8aKE9iOSvIXphXBWGJvWqugzF26b9d+wYAX6yUrKhGGBmkXhntSJUxeKQNEHFhFnCFh
         VLCA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=DOYOq1kt;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712199364; x=1712804164; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=7FljA/ACLrLvEEjUg2rr5zHGT8ulqIASfAuzJFtbOx0=;
        b=Zv6qm+lTE6ipWgxgHPe8a0J8DwQHSVTAhlCn1QeSu5aaQnY5ygFqBWWGKjeN+dkjlF
         1u4NImcyJzCYRgAmu6x5or3LC9uix36aD1WopS7j4DGa402qjKmElK93C2HLEgmaypXe
         zd90yw2XJeNjmqbv2K387ySbzrlK5rcTig/zyL9oMMl5a1QuhEsIiSd2RWYzbXu/fOo1
         BOmZY3gx88EoOUMgGpqHKTEyy/D5e8UNa7aiYT53Tgv8AEg3i6Lc2R4VPpy9HgCS1NMY
         XzxEU7RneobWGWQ9nlFmAqMBHIgU2upXJDcAC31bw8NPhQvi+D6ual6fyWX0Czu9pTDN
         MvQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712199364; x=1712804164;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7FljA/ACLrLvEEjUg2rr5zHGT8ulqIASfAuzJFtbOx0=;
        b=InGL4/gBjl96U/YsdFyrH6Cyu4adZ5fxm/eALGD0dJrOnAdX3jmMK38vh2bPxYbCHw
         F3CZJxaF+YUS8tdw/O9LS+THke0FFw/QbLKx54n/UxGrqkXFbo2nJBMcrsTUGrj+27ce
         EXgmSCLa4PRa17w5tkob7hpBCGH6jLhlJgazq+kjQzIGX2AmGZo5Rzg8TEmfdCcP9YOx
         KamjIwH9GsqoT/6sL7XbMLvqhGqz/LssufaS3dmtxhLuOHEvyLj3y0sDBayBTNfPkR3a
         5zOaIkp7XpwdnSPNmmdpe7bjGVW21YBpmjug9ySkK+uTNl3u/WD/cMfHZl4IqzELzoo/
         URag==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVjNOxMVg8dLRrcvQyAi8uJKaK+II/XjUAmf44StCJ9pSGbZC9Tdrh0FNQMMfXAqest44EIDm9zbHHBFEOFXGJQI13MKCVDIg==
X-Gm-Message-State: AOJu0Yx6YCy2AtTdhhhbutpoS1eQHiYZrGm+59aK69Ws5T7v7l3yx5B+
	lOUQLQQ/rlThA8z0RmnQds/R2Wnkw6a3hKpb+/JP3P57wKqL8mm2M64=
X-Google-Smtp-Source: AGHT+IFal/NbrzEoGbKt4vZnh7FmKG2onIz4Py2385I+W5rciUBywWhR/KPiTK1+IA2SDPWiYCdC3A==
X-Received: by 2002:a92:c56c:0:b0:368:6eac:3520 with SMTP id b12-20020a92c56c000000b003686eac3520mr1514684ilj.17.1712199363906;
        Wed, 03 Apr 2024 19:56:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:178c:b0:368:9d0a:4c26 with SMTP id
 y12-20020a056e02178c00b003689d0a4c26ls348674ilu.1.-pod-prod-06-us; Wed, 03
 Apr 2024 19:56:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUGMUrk3bJBaLo9k5nphdEuflOVhet9bgD7r+kQbAqwaelN2LGt8V0Xs8Hfa1xfwNRgtvNunPmIY0vl8GAuhW6yeqhLe7KE72Q5Uw==
X-Received: by 2002:a6b:e202:0:b0:7d3:54c7:2438 with SMTP id z2-20020a6be202000000b007d354c72438mr138081ioc.14.1712199363034;
        Wed, 03 Apr 2024 19:56:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712199363; cv=none;
        d=google.com; s=arc-20160816;
        b=Rlu1L2kLQMdDUENeOvOnna8am0ErxFHdoN6JJaww6j/9li/t7r1NJOPP9dHvkakl1o
         l96N7o6BlUd/xRvHtfCPQVasOWnRuBCvkd2ysTnTz2S7gdooZmAPKj7JsgqClmfoVfWz
         P7IKLTREuSNMPbomaH/lEIZuvqYUI8P3kuxqKJTc9CP734D/J5MOFs+v5TgTyfWxfgzl
         ZYe/u65+cJ2+XjIcgrl5vg33sNFIN46uqfbUJIoKSv0Uk0pi7MS0cwmd8M2J99nkhNSl
         IzsBFUYnIN/EVM64mE5rHFoftzTCGGqReXBcq2CGAp7bu2RK85sRyz1a4TEMLqXBPdYT
         xJHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=b2H16tqCkJ6i90mQLPDpV1ZsYZDW4KEWWz9R9e+0Oig=;
        fh=0++Z8iPaToeXsiYPhMz2g02LF1kl+WvaMBku9FSLiKI=;
        b=jmZZkA7h4tRLtGkI528i85eAzDcuijuMetKJRKlZnrDSfbA8srKwZ+JpaEYVXFM5ag
         E6MmglANrmdk/8lKBeYrZxJXYzdOrgXiCTtim7hd4fS29HYYdPCsDXZmIagZX9PZP30d
         tTJLFJIU6Pgz+8qGKbMOUlauqvH3O9ki4gfLJ8CLsCx7UnDTLmEGJrm0CHeHHq+TbiFp
         nrV/aMXZKAVYR0BqUM/UhCMQvAkAuEjYeWV9tCjdKTtRUwhaCSpnxv5PCNmgLE5Rs0Ph
         qVkjoBq7WvTX+nVllSbbeBUvi4p8dNoLYM21vNOGwFegkv/oqxwKHpirSNgvkkEucMVp
         b07Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=DOYOq1kt;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id s12-20020a056638258c00b0047f1e1a075esi160943jat.2.2024.04.03.19.56.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Apr 2024 19:56:03 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [50.53.2.121] (helo=[192.168.254.15])
	by bombadil.infradead.org with esmtpsa (Exim 4.97.1 #2 (Red Hat Linux))
	id 1rsDGA-000000012Up-3OOS;
	Thu, 04 Apr 2024 02:55:27 +0000
Message-ID: <5a349108-afd9-4290-acb6-8ec176a80a84@infradead.org>
Date: Wed, 3 Apr 2024 19:55:22 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v6 01/37] fix missing vmalloc.h includes
To: Kent Overstreet <kent.overstreet@linux.dev>,
 David Hildenbrand <david@redhat.com>
Cc: Nathan Chancellor <nathan@kernel.org>,
 Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
 mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
 roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
 willy@infradead.org, liam.howlett@oracle.com,
 penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com,
 peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, dennis@kernel.org,
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
 <20240321163705.3067592-2-surenb@google.com>
 <20240403211240.GA307137@dev-arch.thelio-3990X>
 <4qk7f3ra5lrqhtvmipmacgzo5qwnugrfxn5dd3j4wubzwqvmv4@vzdhpalbmob3>
 <9e2d09f8-2234-42f3-8481-87bbd9ad4def@redhat.com>
 <qyyo6mjctqm734utdjen4ozhoo3t4ikswzjfjnemp7olwdgyt4@qifwishdzul4>
Content-Language: en-US
From: Randy Dunlap <rdunlap@infradead.org>
In-Reply-To: <qyyo6mjctqm734utdjen4ozhoo3t4ikswzjfjnemp7olwdgyt4@qifwishdzul4>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=DOYOq1kt;
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



On 4/3/24 3:57 PM, Kent Overstreet wrote:
> On Wed, Apr 03, 2024 at 11:48:12PM +0200, David Hildenbrand wrote:
>> On 03.04.24 23:41, Kent Overstreet wrote:
>>> On Wed, Apr 03, 2024 at 02:12:40PM -0700, Nathan Chancellor wrote:
>>>> On Thu, Mar 21, 2024 at 09:36:23AM -0700, Suren Baghdasaryan wrote:
>>>>> From: Kent Overstreet <kent.overstreet@linux.dev>
>>>>>
>>>>> The next patch drops vmalloc.h from a system header in order to fix
>>>>> a circular dependency; this adds it to all the files that were pulling
>>>>> it in implicitly.
>>>>>
>>>>> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
>>>>> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
>>>>> Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>
>>>>
>>>> I bisected an error that I see when building ARCH=loongarch allmodconfig
>>>> to commit 302519d9e80a ("asm-generic/io.h: kill vmalloc.h dependency")
>>>> in -next, which tells me that this patch likely needs to contain
>>>> something along the following lines, as LoongArch was getting
>>>> include/linux/sizes.h transitively through the vmalloc.h include in
>>>> include/asm-generic/io.h.
>>>
>>> gcc doesn't appear to be packaged for loongarch for debian (most other
>>> cross compilers are), so that's going to make it hard for me to test
>>> anything...
>>
>> The latest cross-compilers from Arnd [1] include a 13.2.0 one for
>> loongarch64 that works for me. Just in case you haven't heard of Arnds work
>> before and want to give it a shot.
>>
>> [1] https://mirrors.edge.kernel.org/pub/tools/crosstool/
> 
> Thanks for the pointer - but something seems to be busted with the
> loongarch build, if I'm not mistaken; one of the included headers
> references loongarch-def.h, but that's not included.
> 

That file is part of gcc plugins. If you disable CONFIG_GCC_PLUGINS,
it should build without having that issue. Of course, there may be other
unrelated issues....


-- 
#Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5a349108-afd9-4290-acb6-8ec176a80a84%40infradead.org.
