Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBBEQXWMAMGQEACRDD2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id B6FFA5A7C47
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 13:37:46 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id d4-20020a2e9284000000b0025e0f56d216sf3905313ljh.7
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 04:37:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661945861; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ut/W/TMFbE+ZdO7rKz3JCdJrJqqIw8A+5Mh26qw4quZ1fTT+z6yoP0rY4ugYTLxS/T
         og1aiVaSCGS380D/lY4rB4f9AUM2AqxyuJas9XvxwOYT/jvogvGA+XHgIiS/APz9TxbI
         XMHLPeHI8YC0MyE9C+w30YpPK6Bi8REUEOfTjO5E1BtR1rM44qIto6s9bQ6jLjoL0pQ0
         AN+uxWQ6mHEnAzJijZMPaJ7l3kvgqwe9gHTQJlwcSK7/wzuecvihYz9cdDPTlhDOuvgG
         ncOe4Gvxej7vAq43sr6t7zK63nXnQJrIKlZsV/FnPtJCVsEn/5aGd5Ixw1WI7gjE4/0t
         zUug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=bOjgV4tNXSy7x6mm8yVh3Er3ZMIhA5/CHg1/dq5e9eg=;
        b=l68S/fse4apGG93djht9+ZHv1hquU/Zr6b+lhQWIzdcIKl3TXDfhixnfKH/9UjCvnb
         IGBzANd0hhrE/J07/V5brc7DGS9csH+MmliyiiaWWBCoQ7D1prA7IIrODVU5knkM+vv7
         BX76CwlK/TTrN4RccL31V8+TYWGufrMdqB6HmjHQ1jvpH04d+f0NBdc29nAd9axnOhQU
         nSJVkCQHZ/bMPHCtSQ5RqYpJENDlE+NG04jizVnlxwxx1GvgBEGkxP6aNd12UAnBxAF7
         zCsoXBUG91mlhwpXkEut+8XYdM6lL93lPEHLJVcA8wECW+pTiM/h5jBsfVsXD0Ww6RVp
         4cPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=cG2MY93H;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=xkyGZSmb;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc;
        bh=bOjgV4tNXSy7x6mm8yVh3Er3ZMIhA5/CHg1/dq5e9eg=;
        b=LTPuZ35tDf0MuR3nx8WYq4fUp0IosB8pzt7RFy3+l3hp0iXDt05H8NDqr+yObRpjkS
         18jw433tqs7w5l/zFYOR/XROE+WvIvkMxgOST8AEhFWUGm42K10G2IdrSElFJ6v/UKUt
         Hm1RE9NYJvTehQBI+oazrjVRi6rlBu8C/sr+A5C5akBnKTeQ1ACzRdIKZgAj+6wnuaTR
         2lf1HMworUmahPl61bxOeLewMlN9NyVidOQaX1sk+MFY6Hm411ljBah+YwpNJUifCGRD
         GOmHmKrzGfJdEwyc7dc0wMVeJAArPYGCAnsv4leW7DBWOAVATR0heDhYTE2ifzHRBw+l
         v+Aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc;
        bh=bOjgV4tNXSy7x6mm8yVh3Er3ZMIhA5/CHg1/dq5e9eg=;
        b=tnrFxpvfC2xw3T9G/1aVQMHo3v+pKU31trtuhHEGTYvB1Dk9n3cTBwPPwKe7S6O6hy
         /njQ9FFnCNCwoNDHZwI+ASVKackD16mEeUkDtZKmGkyTayNNngDl9rONyo61Fx0jiCxy
         h+W8wOm67UeJ6cAy0WntpHzwThpfOS0hFBoIyyJK+PGj9K9JGFTqcVssTOZolmcT1ekV
         gem+RridDsDVB+p7G2049aJi9+nLMQtPypTQqiKPOmnuivRCjSL7pq9eCV0Gup/QjTgJ
         PBphizTOo2sIoMeo9tHW6KkK2Nrn+W5kZgJzownxk32gL3Os7LAe0Ekha5Ga+iG0zzR8
         z3TA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo08fNXFm7cw5Y5QabAmWIBulH/kbRWzWb+0Rorabbuc6xOMedcr
	p5Ce6mp0Jixx5FA3AGqXiSQ=
X-Google-Smtp-Source: AA6agR4aF5igbwdFaXPqD5/tXrhdbA+th4dal6V5Hp/MdFbvjpc6b3tchcqXQ5teZOcDD2fxqErLOQ==
X-Received: by 2002:a2e:a594:0:b0:25f:e891:b6a with SMTP id m20-20020a2ea594000000b0025fe8910b6amr8942172ljp.242.1661945861079;
        Wed, 31 Aug 2022 04:37:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc29:0:b0:261:d944:1ee6 with SMTP id b41-20020a2ebc29000000b00261d9441ee6ls2567423ljf.0.-pod-prod-gmail;
 Wed, 31 Aug 2022 04:37:39 -0700 (PDT)
X-Received: by 2002:a2e:a593:0:b0:25f:e6ac:c28e with SMTP id m19-20020a2ea593000000b0025fe6acc28emr8893359ljp.485.1661945859606;
        Wed, 31 Aug 2022 04:37:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661945859; cv=none;
        d=google.com; s=arc-20160816;
        b=NJz+TQPP44AjP8X5cI2klLAOAfjxlqwF4fty0zP0hLZQm0mjKkAk5e4w9C3J9lFDZT
         izwBZ8yJLj90a7w7BRO9RS8oGh/o5qC8qi6+bcpusTPwbYDQGyEVZbktcyuNcR2NWJGK
         XeoTqZ++Y+EHXsk3ar7WYNKf7IgRAUjvEA7CqUp1VXGuZZsB56WlWW2TQ9MKtDOHH7P4
         Ly0ERj7Kbxc7203qp1aXjtNcKr9pE39o524cIPSkDCL0BK1yhpArc/7FT+KZO7RKOOC2
         GWALnwUVEylsuTjUzOJ56LWCs0KmMWfkEVzchsPHAxW6AEWQeo4jK4fh/l8RErmQ9Hdy
         bAHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=e4xD++8mKew67TRKWbW4Uu7LwpMCM4MnX8ALzZeQUkQ=;
        b=xMdyHb/DnmOC0Dn/Nyh6JIR8GmY1Cr/M2357iKRHuiE12VCHcKUTbiF0adyF87jADu
         N/ZzfK1F4EPTBaTpfBwT5d2UPbshX2THRf+BMyoNG3Pt6lndCcxih4fuLTvqxyQB6OzA
         rpAmWC6+jgnnwl2/QqGvXef3cjlEOTS5Tq+6E3PiQamOT6SpspvVI3sOfFaKuRhC+Rp5
         idiYeITeDhhvNYa6kJKDlr5y1aIOASb+zkVsUQ83SH0+lWVUFrWDFe05LPVtDIoRT1HB
         FdUXEtwv6JpczRv3meDd/wbYkEleMZjHeTd5yt+D4E4Qeuaj64PIgEk4K4D+xLUjGJ/X
         esPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=cG2MY93H;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=xkyGZSmb;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id t12-20020a056512068c00b0048b12871da5si604068lfe.4.2022.08.31.04.37.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 31 Aug 2022 04:37:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id E8EDA2216B;
	Wed, 31 Aug 2022 11:37:38 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id BABCF1332D;
	Wed, 31 Aug 2022 11:37:38 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id z+9WLAJID2NiAwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 31 Aug 2022 11:37:38 +0000
Message-ID: <5d48856b-3fc2-4203-d964-520aa4d5631e@suse.cz>
Date: Wed, 31 Aug 2022 13:37:38 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.2.0
Subject: Re: [PATCH -next] mm: kence: add __kmem_cache_free to function skip
 list
To: Marco Elver <elver@google.com>, Feng Tang <feng.tang@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org
References: <20220831073051.3032-1-feng.tang@intel.com>
 <CANpmjNPDce6n4scfgwYMz+B2qmJB6+v-2u+Xe5+koxaA=xsmWA@mail.gmail.com>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CANpmjNPDce6n4scfgwYMz+B2qmJB6+v-2u+Xe5+koxaA=xsmWA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=cG2MY93H;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=xkyGZSmb;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 8/31/2022 9:35 AM, Marco Elver wrote:
> On Wed, 31 Aug 2022 at 09:30, Feng Tang <feng.tang@intel.com> wrote:
>>
>> When testing the linux-next kernel, kfence's kunit test reported some
>> errors:
>>
>>   [   12.812412]     not ok 7 - test_double_free
>>   [   13.011968]     not ok 9 - test_invalid_addr_free
>>   [   13.438947]     not ok 11 - test_corruption
>>   [   18.635647]     not ok 18 - test_kmalloc_aligned_oob_write
>>
>> Further check shows there is the "common kmalloc" patchset from
>> Hyeonggon Yoo, which cleanup the kmalloc code and make a better
>> sharing of slab/slub. There is some function name change around it,
>> which was not recognized by current kfence function name handling
>> code, and interpreted as error.
>>
>> Add new function name "__kmem_cache_free" to make it known to kfence.
>>
>> Signed-off-by: Feng Tang <feng.tang@intel.com>
> 
> Reviewed-by: Marco Elver <elver@google.com>
> 
> Thank you for catching this.

Thanks, will incorporate there.

> 
>> ---
>>  mm/kfence/report.c | 1 +
>>  1 file changed, 1 insertion(+)
>>
>> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
>> index f5a6d8ba3e21..7e496856c2eb 100644
>> --- a/mm/kfence/report.c
>> +++ b/mm/kfence/report.c
>> @@ -86,6 +86,7 @@ static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries
>>                 /* Also the *_bulk() variants by only checking prefixes. */
>>                 if (str_has_prefix(buf, ARCH_FUNC_PREFIX "kfree") ||
>>                     str_has_prefix(buf, ARCH_FUNC_PREFIX "kmem_cache_free") ||
>> +                   str_has_prefix(buf, ARCH_FUNC_PREFIX "__kmem_cache_free") ||
>>                     str_has_prefix(buf, ARCH_FUNC_PREFIX "__kmalloc") ||
>>                     str_has_prefix(buf, ARCH_FUNC_PREFIX "kmem_cache_alloc"))
>>                         goto found;
>> --
>> 2.27.0
>>
>> --
>> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
>> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220831073051.3032-1-feng.tang%40intel.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5d48856b-3fc2-4203-d964-520aa4d5631e%40suse.cz.
