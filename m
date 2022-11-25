Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBTPHQGOAMGQE63HT75Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7EC496384C1
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Nov 2022 08:50:38 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id dz9-20020a0564021d4900b0045d9a3aded4sf2214272edb.22
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Nov 2022 23:50:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669362638; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZLPEBWUU0UDNV6HcK48SwFwIJ3PGqXYOVroiE9ory8b92zWh/WS2Ad2Ryez3vmCyMG
         X6rn+dGSiJcptMTJLUvNCGT3vUnn4+ypLk7Dw9oIF4rjoEJMArfXa9lHxcJJzEseQHQC
         9Ghk4/x0XjGb0h4NPRgvBkO1fFYWKDeyAR1es4+B5HaP2sruLBl9tyUr1BB892/3gwNM
         hy5LsWUVTi81bZ46lZWD82apOgp5iBAx7SIRmXexPWqvVv5CGo2iAtQEXLRiXPOlOCF/
         FzndSbHjc0vi8kV37z36Am0S+aIdc5lBnHT1Od1G5HDA8ZzDDtXpht7QUcsqCD/AZ0r/
         L/Gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=7ct262WfbUMg1jfX3TFn+POt24miiNL5+xae7MQUPbs=;
        b=vq6Tap8AlmGNqJzGk7fXl3rTDa13L21qyF5yhqU8j2flizvcHZwHA+xmBXraru4+AM
         UNmSm/ZOQmFFpQLU5hRezOFyue/HvhbBtUIsjBL+sPxwD6tyHXLX0rWld/iXQ6QJ54EJ
         QkaUOkRTz5jYWYfpRsnwT2PuNAQbeI6/spIdTOQeNh3SXzSECYAAqLoocU0g5vMkCcgd
         a6SlPjsiuApJotlhSPP6NlgCqLb8oyxZg50HqiE7cEGV8ntRX4kL6smYeYhZ/uK/W172
         I/SDUi3fNrdi4Xdj03xpeqk4YVG6faDRaPeMQJLdpOEFGGalGqIwWH22qLiRtz57ezgQ
         b67w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=UfA+KLDH;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=7ct262WfbUMg1jfX3TFn+POt24miiNL5+xae7MQUPbs=;
        b=G6dQZ31K0BDz8kgy0zwCN/I2uBELiT/fkX4ujIJvazfvCnP0gn4oevLASmeLiKPrhk
         umMco8tbw/B8UhbfYgDKxGV6Jrww0XUgqbjdh8gs9Bx0m5Td0Zez+563FwN4UxdFIJaI
         09uKvGz1HcrRAHpDGNEziznxO0FRBChjzjTFUBOYBN6aXVoBofy4zzRtHh16sD9SSQex
         D981hTPFFK+xzcClkysAq+TJsZ8ZaDXyIgwuo9uujOeiTKSRcuWiZ/+pRCUnywR0n+sC
         pbUopP4UKkYOOCOFSjF05mCsccmj8PbcoZdaraR/5MQMr5oauwQFutHVVgiIJRUAljnH
         eRjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7ct262WfbUMg1jfX3TFn+POt24miiNL5+xae7MQUPbs=;
        b=qer1T1kUulMu8vGJZcsHtozQR5WtefuG5Eoc90ctvuQ9XOZIXNcBy6hbe4O+48fc/t
         iLqN2dKKND+5AJzZdAbTdHYxBngkPuLXQ0iCEjn+sbWUg6kx8/hskCDve9n66E7DGVCe
         Qx0u813CVvb1Khjo496581O61b5a874BydQmcDBxUq2JOsgfesxxnUri4PPKVaZQhr86
         5jEcGOaCqHfAkf1hOQV6fM01SxBZrSlsPHHWVB9456x23CCMiBnYkUftKKpfcMuzQ7lQ
         rePAgCda9+mGy6acKFzu7/GJXB+aKIL7iNBqhxYEdOb0HV7kXBiMuHDP3Uun/hLlKUdf
         oI6Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pkyNtS4MSeIaoSdFELQ55PNc2+Q3Vn0jP+HqeVTi6FoFywbEowy
	rgy6tIM9vixWQtSGWam5Bfg=
X-Google-Smtp-Source: AA0mqf7u1hGzzldUm8sQIdSgRIuUQ1u+F7OxZk3e0xvmT+wv2jLlk4shRezRRwdaKb/MmhkD2qUZzg==
X-Received: by 2002:a17:906:78c:b0:78d:9c18:7307 with SMTP id l12-20020a170906078c00b0078d9c187307mr33031921ejc.23.1669362637871;
        Thu, 24 Nov 2022 23:50:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3c18:b0:7af:1b1:9648 with SMTP id
 h24-20020a1709063c1800b007af01b19648ls1868064ejg.1.-pod-prod-gmail; Thu, 24
 Nov 2022 23:50:36 -0800 (PST)
X-Received: by 2002:a17:906:860b:b0:7ad:f8e2:ff0a with SMTP id o11-20020a170906860b00b007adf8e2ff0amr30961273ejx.275.1669362636484;
        Thu, 24 Nov 2022 23:50:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669362636; cv=none;
        d=google.com; s=arc-20160816;
        b=hsIuXo+WIGXo2ZZjCrHNPaIdEkSyD4devbc0g3ZDtp3DW0BipCU0TV/QUySYdiCfsC
         uFB/8vuE1m4a/zSg9znApSjLVk5NzajPo4gSUYFIEtjidUbAOiSlEjeu7aQdOK8pPImo
         Unv+AFBeETNYs51llk6HsBnt7Za8IaW4o9rfn4q50m80c/mkLFKQkF19NRx5qf+72nvM
         wTzlJbtKbuospiyBccz9BYWF4Bcltkgc9MjwohxBq21an5Efh5yiCccnTAWuqQ/r99Td
         79bWrnH+9MrmTzQwdqLeED6zYfh0sQY9Ii8PqvUfS3fv1rD6JfQwzxxLYE9XEZlDEFer
         DQ/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=nvdAlIgOG5yqCLw/uf3CjVt0knMtHQ2HViq7mDKGha0=;
        b=e561d4hu6aYoTWID+hWXlHbLIbjqHfoXXIX8OMsmt2TMIQe4RuPZseL0XlVIn4rJ39
         q1docVVprgEgPeO/QauCStr5wgXKIYwPULHnQkPngqsGrUH6VedXBXjdpV6W38waoTGM
         /sL5usgndqK0Qpjy+iaLuYf/Yyf2IlepIT61/nkFijwE/VZp0UmiOJ4AkMomN5bQ+FHm
         o/NmPgKi6dFbszxaHoNhS4YBUi2iR3iaFSlzTjk5HjBoTGsAupnQW1P1nr40p6B7znsd
         ODeCXUfUBzwOvcN0155fK7Smutn0jqujxapxpZ24zvIBJWO6crbAlA3Zp++boUVNNmHb
         an0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=UfA+KLDH;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id d26-20020a056402079a00b00461ad0b1dc0si154851edy.3.2022.11.24.23.50.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 24 Nov 2022 23:50:36 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 0D86E21AE4;
	Fri, 25 Nov 2022 07:50:36 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id E840413A08;
	Fri, 25 Nov 2022 07:50:35 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id kKr+N8tzgGMTFgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Fri, 25 Nov 2022 07:50:35 +0000
Message-ID: <14bd73b0-5480-2b35-7b89-161075d9f444@suse.cz>
Date: Fri, 25 Nov 2022 08:50:35 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.5.0
Subject: Re: linux-next: build failure after merge of the slab tree
To: Stephen Rothwell <sfr@canb.auug.org.au>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 Linux Next Mailing List <linux-next@vger.kernel.org>,
 Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>
References: <20221125124934.462dc661@canb.auug.org.au>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20221125124934.462dc661@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=UfA+KLDH;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/25/22 02:49, Stephen Rothwell wrote:
> Hi all,
> 
> After merging the slab tree, today's linux-next build (x86_64
> allmodconfig) failed like this:
> 
> mm/slub.c:965:13: error: 'freelist_corrupted' defined but not used [-Werror=unused-function]
>   965 | static bool freelist_corrupted(struct kmem_cache *s, struct slab *slab,
>       |             ^~~~~~~~~~~~~~~~~~
> 
> Caused by commit
> 
>   f6e94ad44e77 ("mm, slub: remove percpu slabs with CONFIG_SLUB_TINY")
> 
> I have used the slab tree from next-20221123 again.

I tried the allmodconfig and:

WARNING: unmet direct dependencies detected for SLUB_DEBUG
  Depends on [n]: SLUB [=y] && SYSFS [=y] && !SLUB_TINY [=y]
  Selected by [y]:
  - KASAN_GENERIC [=y] && <choice> && HAVE_ARCH_KASAN [=y] && CC_HAS_KASAN_GENERIC [=y] && CC_HAS_WORKING_NOSANITIZE_ADDRESS [=y] && SLUB [=y]

Wasn't aware it's possible that it will leave a combination of configs
that's not allowed and just warn about it. Oh well.

I'll solve it by:
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -37,7 +37,7 @@ menuconfig KASAN
                     (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)) && \
                    CC_HAS_WORKING_NOSANITIZE_ADDRESS) || \
                   HAVE_ARCH_KASAN_HW_TAGS
-       depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
+       depends on (SLUB && SYSFS && !SLUB_TINY) || (SLAB && !DEBUG_SLAB)
        select STACKDEPOT_ALWAYS_INIT
        help
          Enables KASAN (Kernel Address Sanitizer) - a dynamic memory safety

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/14bd73b0-5480-2b35-7b89-161075d9f444%40suse.cz.
