Return-Path: <kasan-dev+bncBC32535MUICBB2XXRWRQMGQET2GYM6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id AFD7F704E0D
	for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 14:49:48 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1ae40139967sf4682055ad.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 05:49:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684241387; cv=pass;
        d=google.com; s=arc-20160816;
        b=UFf8rWagpIk5L8LvJSb7XIUprxC/Dc+niU5Ykz1Ib1auqNPLJV+E/71279HRMQUrkq
         HI450XCJiDF8MlImRfJ+mtKnCZfcrF1f9Gp9IEJdb07aA0IfFuFDtPXdy185AcsZQTef
         e5tF0RLx39A9jja6bifSynG+hBfEg++f6YYShwixnBblXV3hELUyhDsSRnGurNJ+6/yO
         TDH4ilfIRQcNuVjH4pCL1NDXaEwqSPu0q0hwTx21QeDVcsRMfx1KgGFwX3MiE7KXITGR
         BsfBQMguStQuHxrbU6mS0yey7O/YAnBdQBJwZeK7/bobeCk+ql095UhpVKipZxDDcV6C
         jlxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=2+kgC8oynOrfwNMkYup8H7sk0iyNhyx0feX/7QG6gSQ=;
        b=z2OmqalJwOs/9tScRmNTVPoKCO1cx58XLDZM6OQFu90XDsmTbab2Xf02BuJ/yE50xU
         aRGEtkgxmAvs4dQrC6YkLxeYBLSry4XteqU6snVXXA2JNGAs+0kGqnpodoA3QNn7VOAZ
         b9cDKTn+A0on5hsY+GB7FX26PGbJT7czRZHvMTp6caypc6JgDbQGBOHrD/j5IoZlJHVZ
         sZZ9Oo5TMT5Ibx5tbMCel8XJWWMKUxalGx0T9mSlTZIG4fMZH2CGVDOD/2sbHJan7dMb
         rU35DejsynQlxb9dx9MfY8ZL9eEhH5AA7UlNf47EHQ6uNesDGyebnY3KnZRvAh4Xtji0
         TXrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=TPoTfPGy;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684241387; x=1686833387;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:organization:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2+kgC8oynOrfwNMkYup8H7sk0iyNhyx0feX/7QG6gSQ=;
        b=G1W6M1AcSxqhIKxS5O77hHim0UMuJSlLPwGKmieFpjfmG9gfI9y0PrAQVhiHmOS4N7
         QNctwU0HTgYzD4/YiM00ZlncRgJgSwT+NQbMv+sfiPaTlmr5GUIJbC3VLvF1XLUsJpF6
         coiRJyXlj8XkEHmR3tdoVy+SHDvJlD4duBnRmUoud6++Q4XbDP3Wc54BfcHQLfOmHW3I
         kemuz0BpDp21AdSnWeDDzm2wwWSTvyb+mO6/sjRwzJFkoX6ZmgygSwpGa8tFHRsCLavd
         eo1+Md91Hd6qb1bfBwrcZwaB+sHP2wcfJdv0onR/tQk4d33aoIeRp6ouFnF9QAYz6UVb
         oHvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684241387; x=1686833387;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=2+kgC8oynOrfwNMkYup8H7sk0iyNhyx0feX/7QG6gSQ=;
        b=h0HfjxlcB/Q2VkqrFwUd5SffGpEO5gDaQCP33SrwLZzzDZ4jqqfuSP0Yn8q7DK6NL6
         usbd//5QHFJGNQl2a2PUjHjBWPUuDkC5bfwJIKyYdO7ZvacMg7mLYfY3dfgdSrqocKBK
         rxBpZPQY8cMav2H5rlHK2EPtP0DikF+iWU5/Vgo1BdGzeec1+jDI5NsUKujZBnAfbiUk
         TzgiWtJW2RuAJriMiyBvaf9F6v0gn0NIBTSjHvEqsGnw2otdLpOb3b+vexCfEx4dt7ri
         8B/FcAujopkAeY/R7iBdco970MKzTkBGchv+J6YUb5etFDbQrGHD7xwcNPrMqCPBgapj
         wdZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzkCxYjBH7wbyOce87+klE0kt255y7vMQm3FlUAlu1kwon6T97e
	ckgtTQz5qImpDsJJmSMlMPA=
X-Google-Smtp-Source: ACHHUZ5whGrM2Byil9XM9/Uzu91Q8a3agHv0+wKxsVXlteWBvD6oOXoJRB3E+t/Dqg0zSj3hMv8Q0g==
X-Received: by 2002:a17:903:2341:b0:1a6:c58e:9b9e with SMTP id c1-20020a170903234100b001a6c58e9b9emr14038667plh.7.1684241387035;
        Tue, 16 May 2023 05:49:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:5d8b:b0:24d:e123:1ea5 with SMTP id
 t11-20020a17090a5d8b00b0024de1231ea5ls1141669pji.1.-pod-prod-05-us; Tue, 16
 May 2023 05:49:46 -0700 (PDT)
X-Received: by 2002:a17:902:ecc5:b0:1ac:6882:1a6f with SMTP id a5-20020a170902ecc500b001ac68821a6fmr38717753plh.30.1684241386004;
        Tue, 16 May 2023 05:49:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684241385; cv=none;
        d=google.com; s=arc-20160816;
        b=T7SD4LCjYmelxySbvKw6G83XwBgi1aIpX5s6Xq3Mcj0Id8OYrXXXxKCFhTZER1RHKA
         nj27Nqkx8t4PARhgkcKaJI+nrbLZvYhYP1XStEYVJsl7H3HFCcuhBnpTWBamfM2Tx9Ua
         1Il1RDPgJ+JrldxXo+bnmRsEOJJMWAyay2pwz2ZAZyHrdkDdldAt42tEfBG9EzA/Nbcv
         uRTxFnsJVMvRhNmO2/IiI4t+mY9ifZZzp0e1gF0tjV/B+wjnMzDzB2e7MFzLMA4QEci3
         6s4sd88XZ6AwoKIjzibv6oUSytvVmtrdKLSV42yf0j0VxHQ2O8c1F5z1/knc9Cs+ZFSR
         K8cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=P6ENP1TOkkkwTyntwJbblY7IR/X8Hu2k3+7/H7vMwQQ=;
        b=Ogr+2uBtoEovEfdtKM+x2blz5R5imTnu8D7Bti6BQXa2fd7QnQtetphMkuTu+6gFmA
         QhLvnU9WcIX8NjLiEnO9YbHz3DYguOPzwy+3YWQ81RQOljg/CXb89kQWjKILV4Gf57TL
         J6HZ3kzSTHB94JCl6njulbKI0e1wEZBHdbYsrbaU1Qr9HxCfKgtf0Z/8ZVMU/pyVJ/uj
         48XBxZEDo3PsSkA8pqP7GPdnmGr+A0hB+9DEWqFaJKXlUwoQzczHB6rj7TGXNwZj7DBh
         7osOrjgywEKerLUoRXOBkLnOQQL2bKNemPqhsove6iyf5yUK1gKtHZgbEdTyfPsM+uGu
         /sPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=TPoTfPGy;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id kx5-20020a170902f94500b001aaf7c46645si1040661plb.11.2023.05.16.05.49.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 May 2023 05:49:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-393-4JlQXSncN66ad3NpmbReuA-1; Tue, 16 May 2023 08:49:41 -0400
X-MC-Unique: 4JlQXSncN66ad3NpmbReuA-1
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-3f4221cd284so36891735e9.0
        for <kasan-dev@googlegroups.com>; Tue, 16 May 2023 05:49:41 -0700 (PDT)
X-Received: by 2002:a7b:c419:0:b0:3f4:a09f:1877 with SMTP id k25-20020a7bc419000000b003f4a09f1877mr14616488wmi.23.1684241380830;
        Tue, 16 May 2023 05:49:40 -0700 (PDT)
X-Received: by 2002:a7b:c419:0:b0:3f4:a09f:1877 with SMTP id k25-20020a7bc419000000b003f4a09f1877mr14616472wmi.23.1684241380418;
        Tue, 16 May 2023 05:49:40 -0700 (PDT)
Received: from ?IPV6:2003:cb:c74f:2500:1e3a:9ee0:5180:cc13? (p200300cbc74f25001e3a9ee05180cc13.dip0.t-ipconnect.de. [2003:cb:c74f:2500:1e3a:9ee0:5180:cc13])
        by smtp.gmail.com with ESMTPSA id x8-20020a05600c21c800b003f4f8cc4285sm2236830wmj.17.2023.05.16.05.49.39
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 May 2023 05:49:39 -0700 (PDT)
Message-ID: <342d76b0-a94f-902a-c701-04a1e477b748@redhat.com>
Date: Tue, 16 May 2023 14:49:38 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.11.0
Subject: Re: [PATCH v2 1/2] mm: Call arch_swap_restore() from do_swap_page()
To: Peter Collingbourne <pcc@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>
Cc: =?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, "surenb@google.com" <surenb@google.com>,
 =?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?=
 <chinwen.chang@mediatek.com>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 =?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?=
 <Kuan-Ying.Lee@mediatek.com>, =?UTF-8?B?Q2FzcGVyIExpICjmnY7kuK3mpq4p?=
 <casper.li@mediatek.com>,
 "gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
 vincenzo.frascino@arm.com, Alexandru Elisei <alexandru.elisei@arm.com>,
 will@kernel.org, eugenis@google.com, Steven Price <steven.price@arm.com>,
 stable@vger.kernel.org
References: <20230516023514.2643054-1-pcc@google.com>
 <20230516023514.2643054-2-pcc@google.com>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <20230516023514.2643054-2-pcc@google.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=TPoTfPGy;
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

On 16.05.23 04:35, Peter Collingbourne wrote:
> Commit c145e0b47c77 ("mm: streamline COW logic in do_swap_page()") moved
> the call to swap_free() before the call to set_pte_at(), which meant that
> the MTE tags could end up being freed before set_pte_at() had a chance
> to restore them. Fix it by adding a call to the arch_swap_restore() hook
> before the call to swap_free().
>=20
> Signed-off-by: Peter Collingbourne <pcc@google.com>
> Link: https://linux-review.googlesource.com/id/I6470efa669e8bd2f841049b8c=
61020c510678965
> Cc: <stable@vger.kernel.org> # 6.1
> Fixes: c145e0b47c77 ("mm: streamline COW logic in do_swap_page()")
> Reported-by: Qun-wei Lin (=E6=9E=97=E7=BE=A4=E5=B4=B4) <Qun-wei.Lin@media=
tek.com>
> Link: https://lore.kernel.org/all/5050805753ac469e8d727c797c2218a9d780d43=
4.camel@mediatek.com/
> ---
> v2:
> - Call arch_swap_restore() directly instead of via arch_do_swap_page()
>=20
>   mm/memory.c | 7 +++++++
>   1 file changed, 7 insertions(+)
>=20
> diff --git a/mm/memory.c b/mm/memory.c
> index 01a23ad48a04..a2d9e6952d31 100644
> --- a/mm/memory.c
> +++ b/mm/memory.c
> @@ -3914,6 +3914,13 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
>   		}
>   	}
>  =20
> +	/*
> +	 * Some architectures may have to restore extra metadata to the page
> +	 * when reading from swap. This metadata may be indexed by swap entry
> +	 * so this must be called before swap_free().
> +	 */
> +	arch_swap_restore(entry, folio);
> +
>   	/*
>   	 * Remove the swap entry and conditionally try to free up the swapcach=
e.
>   	 * We're already holding a reference on the page but haven't mapped it

Looks much better to me, thanks :)

... staring at unuse_pte(), I suspect it also doesn't take care of MTE=20
tags and needs fixing?

--=20
Thanks,

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/342d76b0-a94f-902a-c701-04a1e477b748%40redhat.com.
