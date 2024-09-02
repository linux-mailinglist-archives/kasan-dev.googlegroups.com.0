Return-Path: <kasan-dev+bncBDXYDPH3S4OBBXP32W3AMGQEVYCNMGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id D9987968288
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Sep 2024 10:57:04 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-53341717c62sf3580849e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Sep 2024 01:57:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725267424; cv=pass;
        d=google.com; s=arc-20240605;
        b=DvFtDfgf9vg2gIDZLryPAvAYJa05X2EAP4Qt+Nke2/fr5oCA6MM4wDJNmgzv1Q8Jvt
         c/X967ExvJryMNhlayaxtuT7hmwDx1NfTxlZHyuiGJGqlpSOvXI4SratoGgJNq4QZQWv
         aSsGi+/1FvJRqXCrGDkUEtZuDkF6G0QUa/iwadngNVPoXBz6+0+BEWH3EODgYFG/JL+Z
         kdjXuUcP3jqpbX7202LyZyfnWDEDMIrXP1tgAsive4NaP3JsB1BKeogvol1eyGjcaZlZ
         aL3Ze8S4ovf8nFEqT57syfCbC9kWWFKahvpT6U306n8QaENbbzgb8qg1AuMUI7AP9XNc
         uPtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=GNNpyuE+VtzQpWzoI1qFsQ0jzXpScIa+ie7wYeb0EjY=;
        fh=UVMuqYj63h2FV5ggtHzxRJ4bwFlUwYYsGcIo8L/ZpgU=;
        b=C44dErWU1YyTHc/lZq/EhkJRwvECUWVfet9xyLGQVdA7dWnyQx75D9M9wamydk8Qbl
         DD8NEj8E3a01HySDFkTyTF7D9/YhC/Bj5IpWMJwBZORR25EEWvazYORTeZUT1yvZElW3
         w9jxUA9MRZ2kgfhFpvSnpENwpz11fb+j9PPt1S0DX/Odj9b5flVKy4fH0spzOyE8hqQk
         PU1T4RPHzupGP8dJ/zC2h+epLBaPpXMw/WCePc4K1zUsXtuDUs1IP7YysPUFXRJ3OF04
         jwX3uZXL8w7VJEwx98DUegMk5ch1QLIvyltU5AV/uiX0oVjun5hG/PZT5oWpDm7Fbsgc
         KXsQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=IaU8guUU;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=XxZIUg8E;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=IaU8guUU;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725267424; x=1725872224; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=GNNpyuE+VtzQpWzoI1qFsQ0jzXpScIa+ie7wYeb0EjY=;
        b=W9IwPESaye603JWBFn8Uj9YE39awqGOiv4Sr/5GVIp08m6Hy3dmMlGhkM8ckLcgSD8
         Ug3CkejUoq/8PDF+3ESHUun7ForB4LT++KVfEUvDvQwCseH0+OkaAH+TSOxdDJlLFVUG
         g+0YzsmEbMVc4zjR/8SO8snFfKRTvpS+jcC/9Fd0PXozGH5V8nSKkFYqmH69E2Aotuqt
         opkU6KS1Osm5LtRR6wcfVORsVTC7USGdVK728qP5sQsyQh2FQ0MbRDOzcqHWE42J6wqQ
         paqbgFOrarjSNZe4ZOHCJqba85OMPubr44+cwbpIw8cekaEgU6wI4uC8orcqT7RwGqJf
         xqGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725267424; x=1725872224;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=GNNpyuE+VtzQpWzoI1qFsQ0jzXpScIa+ie7wYeb0EjY=;
        b=rTyZS22f1USEybyDvNWwG9IFtW1LgCcGv+FR/A8nEcM6TLyRaW8FzdOj3k3uZoRP27
         FtREkkWLHFMzdElEMj68fFXlnkazEYU/ooQ/Uu1S/dDYVSvpVv0of0o2zJ2ll1C8GtIB
         dut/JQG7VCLkyD5rnt0W/WOpftKHzalgmu61PKSKZACRAxd3uwxB9k+7AiGmxEqLCn1j
         cg4F2XlGb0fE95r/q7fTXVM1zXEr81iXSMNX+swkWYnobfCw+KMwXh+nZzDmU6B3OgeY
         SiZE6n1/0hdtIRSK1Kdooot3WrJ9Al+llKbY/ju+3q1+nfSXUDI18byhH/Ccr578EtV7
         CGag==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXlA75lZhREUNku1ub1upuRJ6HUwD8T8JrVV00jU6WH7EGdBleI6xDpm7lZmaj8hUxNciqA8A==@lfdr.de
X-Gm-Message-State: AOJu0Yw9rvFAmJycM9onDdvvVnVkhDK2px7pRswsBJ5Qz0ru6Jl+imuc
	wpG9/qLLOwkdcM4RyS1BY/48CohOEDCbP83ksHFKth45Ug/GqGSt
X-Google-Smtp-Source: AGHT+IEnCCNS/abMkiqIU7y4x9xdRdWi9CWGwCZ6FDuS6g06OyeLdEOE9vcYX6RPUbciIAkn7G+v8g==
X-Received: by 2002:a05:6512:118e:b0:530:dfab:930c with SMTP id 2adb3069b0e04-53546b34ddcmr5844166e87.28.1725267423003;
        Mon, 02 Sep 2024 01:57:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b90:b0:52e:9bbf:bef3 with SMTP id
 2adb3069b0e04-5353d640922ls111098e87.0.-pod-prod-04-eu; Mon, 02 Sep 2024
 01:57:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU4y3CzlUGd0ks1F8c5nJlPjbp7tlzCbCLhb9lwZA5XToAvfbajouxskFKEOksMGiwFwCivEMnjQZw=@googlegroups.com
X-Received: by 2002:a2e:a586:0:b0:2ef:290e:5b47 with SMTP id 38308e7fff4ca-2f629041560mr44906341fa.15.1725267419854;
        Mon, 02 Sep 2024 01:56:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725267419; cv=none;
        d=google.com; s=arc-20240605;
        b=Mx0tI4Eup0hnnfc1Aqq9hRg4ipAZGGyut0Qo34x62d8OmO6GYSkeho7jU2N/9C8Ooc
         xWdcvcC2UPJW122pjx8DaET1w7Zf7jwtHG4kfPqOBhgr9vrVSHKJrYYxoE/Sc5hqM5ui
         jd83Ksn1mJ0QG+pfQS+GPZ98Aqw7x9DJfSzav8FSLntZicQvgHAs4TlZ1EC3BHZ0Jmo/
         hqRh+xhUY7TgvkPJe82vB+c5gzj3a3sRB6yO4tKB2KDJqeV9lXcqcw+9AqbZM/RIKMru
         aRp5EYNphx8/88RlGO6RllmSkLFuJNlq61DFLWTERqRaM5AJwSUwaw4o7Fg8Vr/tL80/
         Z4TQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=WSA9U7lugzB3ukAjYh0xJQNLZfRIb4q7TpGenVYMhdM=;
        fh=Dp38dablOrLGKvilHffAjEcdhF/8mqcqjWmQdtOySk0=;
        b=O6JWVotcI/q+dpYMdBacZCOlb7JxgjTeKv5ZYatH9o37MTCVEAIEMxoB9xhgO44QAv
         ZKtOtaoDUxR1DuVAAF2eTWSRki4ZMDAQIrhl2z+sWqdYfCxjPrF0S6BEHu6h6hL8Ehov
         qkxQr9msKBxkAo1kitIImztqaaEtiekkIivoGoLmEN0mWXLGbeEjKqNaOsCc2nvlOkmV
         hC+hI0O31FXTS8WPo6IGIUv6gFTqOl4klcr3N3IyjpfixOVfnAj0vMkenZ4D5ZkCCdQl
         FE+RXqJ7Cq+eQ+oQLV7IquQZKw+EXIMfGXi5rAiQwjL1Q0sFNrd1j9vGbBExbA69rS8C
         RXWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=IaU8guUU;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=XxZIUg8E;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=IaU8guUU;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f6151747eesi1977851fa.6.2024.09.02.01.56.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Sep 2024 01:56:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id C0E8C1FB9D;
	Mon,  2 Sep 2024 08:56:58 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 7F02913A7C;
	Mon,  2 Sep 2024 08:56:58 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 3J9bHtp91WZhSgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 02 Sep 2024 08:56:58 +0000
Message-ID: <ec7bca4c-e77c-4c5b-9f52-33429e13731f@suse.cz>
Date: Mon, 2 Sep 2024 10:56:57 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 1/2] mm: vmalloc: implement vrealloc()
To: Feng Tang <feng.tang@intel.com>
Cc: Danilo Krummrich <dakr@kernel.org>, "cl@linux.com" <cl@linux.com>,
 "penberg@kernel.org" <penberg@kernel.org>,
 "rientjes@google.com" <rientjes@google.com>,
 "iamjoonsoo.kim@lge.com" <iamjoonsoo.kim@lge.com>,
 "akpm@linux-foundation.org" <akpm@linux-foundation.org>,
 "roman.gushchin@linux.dev" <roman.gushchin@linux.dev>,
 "42.hyeyoo@gmail.com" <42.hyeyoo@gmail.com>,
 "urezki@gmail.com" <urezki@gmail.com>, "hch@infradead.org"
 <hch@infradead.org>, "kees@kernel.org" <kees@kernel.org>,
 "ojeda@kernel.org" <ojeda@kernel.org>,
 "wedsonaf@gmail.com" <wedsonaf@gmail.com>,
 "mhocko@kernel.org" <mhocko@kernel.org>,
 "mpe@ellerman.id.au" <mpe@ellerman.id.au>,
 "chandan.babu@oracle.com" <chandan.babu@oracle.com>,
 "christian.koenig@amd.com" <christian.koenig@amd.com>,
 "maz@kernel.org" <maz@kernel.org>,
 "oliver.upton@linux.dev" <oliver.upton@linux.dev>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>,
 "rust-for-linux@vger.kernel.org" <rust-for-linux@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>
References: <20240722163111.4766-1-dakr@kernel.org>
 <20240722163111.4766-2-dakr@kernel.org>
 <07491799-9753-4fc9-b642-6d7d7d9575aa@suse.cz> <ZqQBjjtPXeErPsva@cassiopeiae>
 <ZqfomPVr7PadY8Et@cassiopeiae> <ZqhDXkFNaN_Cx11e@cassiopeiae>
 <44fa564b-9c8f-4ac2-bce3-f6d2c99b73b7@suse.cz>
 <ZtUWmmXRo+pDMmDY@feng-clx.sh.intel.com>
 <ZtVjhfITqhKJwqI2@feng-clx.sh.intel.com>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <ZtVjhfITqhKJwqI2@feng-clx.sh.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Rspamd-Queue-Id: C0E8C1FB9D
X-Spam-Score: -3.01
X-Rspamd-Action: no action
X-Spamd-Result: default: False [-3.01 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	ARC_NA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TO_DN_EQ_ADDR_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[24];
	TAGGED_RCPT(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	TO_DN_SOME(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[kernel.org,linux.com,google.com,lge.com,linux-foundation.org,linux.dev,gmail.com,infradead.org,ellerman.id.au,oracle.com,amd.com,vger.kernel.org,kvack.org,googlegroups.com];
	RCVD_TLS_ALL(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	DKIM_TRACE(0.00)[suse.cz:+]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=IaU8guUU;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=XxZIUg8E;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=IaU8guUU;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 9/2/24 09:04, Feng Tang wrote:
> On Mon, Sep 02, 2024 at 09:36:26AM +0800, Tang, Feng wrote:
>> On Tue, Jul 30, 2024 at 08:15:34PM +0800, Vlastimil Babka wrote:
>> > On 7/30/24 3:35 AM, Danilo Krummrich wrote:
> [...]
>> > 
>> > Let's say we kmalloc(56, __GFP_ZERO), we get an object from kmalloc-64
>> > cache. Since commit 946fa0dbf2d89 ("mm/slub: extend redzone check to
>> > extra allocated kmalloc space than requested") and preceding commits, if
>> > slub_debug is enabled (red zoning or user tracking), only the 56 bytes
>> > will be zeroed. The rest will be either unknown garbage, or redzone.
>> 
>> Yes.
>> 
>> > 
>> > Then we might e.g. krealloc(120) and get a kmalloc-128 object and 64
>> > bytes (result of ksize()) will be copied, including the garbage/redzone.
>> > I think it's fixable because when we do this in slub_debug, we also
>> > store the original size in the metadata, so we could read it back and
>> > adjust how many bytes are copied.
>> 
>> krealloc() --> __do_krealloc() --> ksize()
>> When ksize() is called, as we don't know what user will do with the
>> extra space ([57, 64] here), the orig_size check will be unset by
>> __ksize() calling skip_orig_size_check(). 
>> 
>> And if the newsize is bigger than the old 'ksize', the 'orig_size'
>> will be correctly set for the newly allocated kmalloc object.

Yes, but the memcpy() to the new object will be done using ksize() thus
include the redzone, e.g. [57, 64]

>> For the 'unstable' branch of -mm tree, which has all latest patches
>> from Danilo, I run some basic test and it seems to be fine. 

To test it would not always be enough to expect some slub_debug to fail,
you'd e.g. have to kmalloc(48, GFP_KERNEL | GFP_ZERO), krealloc(128,
GFP_KERNEL | GFP_ZERO) and then verify there are zeroes from 48 to 128. I
suspect there won't be zeroes from 48 to 64 due to redzone.

(this would have made a great lib/slub_kunit.c test :))

> when doing more test, I found one case matching Vlastimil's previous
> concern, that if we kzalloc a small object, and then krealloc with
> a slightly bigger size which can still reuse the kmalloc object,
> some redzone will be preserved.
> 
> With test code like: 
> 
> 	buf = kzalloc(36, GFP_KERNEL);
> 	memset(buf, 0xff, 36);
> 
> 	buf = krealloc(buf, 48, GFP_KERNEL | __GFP_ZERO);
> 
> Data after kzalloc+memset :
> 
> 	ffff88802189b040: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff  
> 	ffff88802189b050: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff  
> 	ffff88802189b060: ff ff ff ff cc cc cc cc cc cc cc cc cc cc cc cc  
> 	ffff88802189b070: cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc cc  
> 
> Data after krealloc:
> 
> 	ffff88802189b040: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
> 	ffff88802189b050: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
> 	ffff88802189b060: ff ff ff ff cc cc cc cc cc cc cc cc cc cc cc cc
> 	ffff88802189b070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> 
> If we really want to make [37, 48] to be zeroed too, we can lift the
> get_orig_size() from slub.c to slab_common.c and use it as the start
> of zeroing in krealloc().

Or maybe just move krealloc() to mm/slub.c so there are no unnecessary calls
between the files.

We should also set a new orig_size in cases we are shrinking or enlarging
within same object (i.e. 48->40 or 48->64). In case of shrinking, we also
might need to redzone the shrinked area (i.e. [40, 48]) or later checks will
fail.  But if the current object is from kfence, then probably not do any of
this... sigh this gets complicated. And really we need kunit tests for all
the scenarios :/

> Thanks,
> Feng

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ec7bca4c-e77c-4c5b-9f52-33429e13731f%40suse.cz.
