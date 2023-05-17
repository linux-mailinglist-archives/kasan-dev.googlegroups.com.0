Return-Path: <kasan-dev+bncBC32535MUICBBR5ESKRQMGQERTUAROI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E822706309
	for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 10:37:29 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-33338be98cdsf3171675ab.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 01:37:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684312648; cv=pass;
        d=google.com; s=arc-20160816;
        b=lVmY3uerMRHJqmLQBLDi1cstdJRxmcc2LQfpq1mwn5YeCSoaMtGgw7bY6JnMhnpRy8
         RvpW3NDx2qe/7wd/ymRAYcxrhi5GnxlD8V++UZgLCziTChjv63ziWLVi5wB7MUCrmLY6
         CiMC6w0EONUcmKVTDpU0zX1/1nDjq8/wejGmCu9jdPv0KBUvEVx66n/iHO0zO6B3Edna
         eg9ZOwhKxfunLuznNWUM/DImFVsxjYoZK8wNljvqJzLyquIGnSicEfezWVwiATuDKqYN
         /D532ulN8m0j5x2iWr5ZC3gUglxvMvk7d5CpKN4/2vKP4kUg+0CE4DRFttlUupfDW7Qo
         G1cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=G9ylRtF5bUutnEO1++TQZ8WyW5mppTBGVHuR7hBSFME=;
        b=TIv6VkHKdpAmzIgN46jKRK/P7uAQuL0lsAgyc2b59BwVHTnCQ3dgk4XmnayHNW7i/8
         DxKGkB9jTUlHXVqSMnY02In+3odUAqq31uPxGSneXnB+F8G0NhLRboYcaStyz0xbb56U
         XE2iTqaE6Jz1qXYdmmyk84cvzBclHEvd5cltAE0vHKKdBXS+5Xd+ZOB2pQnpICKQNr8i
         Xe0H/ryk+moYU9w9ix3z3kYJlELY2nTaXn62ZVqrNVNxQ1eUp1MZlvGukcbfyifbmeHt
         xkEYKzIuGb+OFBiMbR41Ft5O6qJG9BBeR6mhELAnjzBfC69YdPPibAnz5yYcgE1j70Pk
         LJxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=g8h+buq4;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684312648; x=1686904648;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:content-language
         :in-reply-to:organization:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=G9ylRtF5bUutnEO1++TQZ8WyW5mppTBGVHuR7hBSFME=;
        b=j9NGuKEYewSnHzX5UTDFYrjxdp8rjEF9su1sL2JEV+rlgbqnt9BfxgAaGsknET67I/
         +NDL26wAlcZ5kI6E8B7WARZJDaiSbCebCKaTJoAdO7GDth1EQZba7I63DxqmWcR+BJYs
         An+nx2ZQt34BzndpfdYXBg8ZrT1xno6+Sl+qwfQKeSAbXYsGSqDvJLQPvUM/Uv8JbBbe
         pgeYixJVqGiWmHLlartT7Ub0jd7wezdrbyj8prmo+6rPphsSYArNQD+NR3t7aBGJoihS
         F2lEGGaQwlxtXhSQMQJD3PEBrjCqiWPCJkspglUAdP4tu2ufeynjUTKCnx441RMB8o4y
         s3dA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684312648; x=1686904648;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=G9ylRtF5bUutnEO1++TQZ8WyW5mppTBGVHuR7hBSFME=;
        b=dAjDQDoKIDwqcLrVPYSgwIjR+zgJYe0oo/LpB9L9001yYO8zhoNibhYShLCxluCQPF
         PpinAliOyNkzwIkxSXKcDUs4byp9ReWxXQQ8uZqOE6iwL4q97fjo4Dq+5rwOXcod5Koa
         PtaZySDJ/y03m6A6qwTcB7uwUYeDIoB7HV/H57HUD7GZik34Y3bE23aAkIWpBkitKrzh
         UVuz3T0i1ws8gNzblQIbnjlQBPGGdGU720c9fzKgCPziri0MU93zW9D58b9MHAyVzdqv
         /uZhxVuyVUZC0OAgmqgvdyjYIZVHX+DyLRxDH+7e75X6lswiTTt3jN7gxTLmyc0+Vbh0
         s6Eg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyHpznR6atwBnL+7drrnQOO0CaT7aAFZG5u+4OE5C+ex7QVwZWU
	4R1LpL04E2UP4tKk99x27j4=
X-Google-Smtp-Source: ACHHUZ7TltvVRoMSWwndeddjYT4AWLcWhEqH2FH5HbBvsxKhWcDMFrvV13TT8Iz5/9z/nhxlFBgwiQ==
X-Received: by 2002:a02:6349:0:b0:418:8a6c:ae98 with SMTP id j70-20020a026349000000b004188a6cae98mr7012926jac.4.1684312648082;
        Wed, 17 May 2023 01:37:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1043:b0:32e:2d9d:f290 with SMTP id
 p3-20020a056e02104300b0032e2d9df290ls1022604ilj.1.-pod-prod-07-us; Wed, 17
 May 2023 01:37:27 -0700 (PDT)
X-Received: by 2002:a92:d5c1:0:b0:333:eb18:2b75 with SMTP id d1-20020a92d5c1000000b00333eb182b75mr1397853ilq.28.1684312647436;
        Wed, 17 May 2023 01:37:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684312647; cv=none;
        d=google.com; s=arc-20160816;
        b=QdvCdY/uAOU9cyyYya/ediA6PuJYPLVNwNNDRREzj+qFci/fjM56AQZcAKk1TMCZo0
         JOtQq+TqMc6O8FYrqFotq/snkmQo9wgNyBwjAmUAfKfc4nCbKH7qZk5b9iDRyyau3+dG
         J2sHudKD+bvt+I2bejTuVmyR8MSZ+We30t6efzIw50O5R5Og3KzDi53ICgPoVTzRC9aK
         so38lx75yzgVkQfrtnvffkHjvRpeqePTYygA3TJ4h0VPDo0vzWHyM9IP/6avFbfB68pN
         zz027OSpPDj2QwJx6dMCVne+Fd1LKSxt6J5LyZn8+6S1o4IgLWDLR9bfYdFntgwMQon/
         iDGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=2WdsMZLBHDWxr+KE0TdL6QcbjY/uUPjF0RV3EGhnsZw=;
        b=g+G6Ijou9QvZPVXxitjvp20QrevEplI1WN5T9Ub3GYedXOOyV65vwub92ylbWgATdR
         mUKgGZfE3K8jODlHOyOk/xmvWKd9X+SfAPTdBHZki21q81y+sfWiN1flx5+XbCcyqvAy
         6jxXovVJBuUJnfNBKg8jbg7/wNmKWLbh8TbiuLbQ78K0ip2M4LxhQNZlsM/B0FBeL+lv
         hJ4nW24a2cJeJGep1dqJzpT+E7rZlfy7oGHRqFFPu8cYkl8jHrMZfMjBdnvwGfrFeE/4
         t2L8/pctUZ8JiWocD2O/AfrYN83T0dXaeeZT8YMcapInF2VXGJNUjOWNxrDMI2NNU9w9
         RygA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=g8h+buq4;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id a4-20020a056638164400b004165078c231si2396955jat.5.2023.05.17.01.37.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 May 2023 01:37:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com
 [209.85.128.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-115-kAWhF1jEMcS7PT853QLhFw-1; Wed, 17 May 2023 04:37:25 -0400
X-MC-Unique: kAWhF1jEMcS7PT853QLhFw-1
Received: by mail-wm1-f69.google.com with SMTP id 5b1f17b1804b1-3f422dc5fafso3182035e9.0
        for <kasan-dev@googlegroups.com>; Wed, 17 May 2023 01:37:25 -0700 (PDT)
X-Received: by 2002:a1c:c917:0:b0:3f5:e88:3c47 with SMTP id f23-20020a1cc917000000b003f50e883c47mr4936719wmb.16.1684312644149;
        Wed, 17 May 2023 01:37:24 -0700 (PDT)
X-Received: by 2002:a1c:c917:0:b0:3f5:e88:3c47 with SMTP id f23-20020a1cc917000000b003f50e883c47mr4936689wmb.16.1684312643761;
        Wed, 17 May 2023 01:37:23 -0700 (PDT)
Received: from ?IPV6:2003:cb:c707:3900:757e:83f8:a99d:41ae? (p200300cbc7073900757e83f8a99d41ae.dip0.t-ipconnect.de. [2003:cb:c707:3900:757e:83f8:a99d:41ae])
        by smtp.gmail.com with ESMTPSA id g3-20020a5d6983000000b0030795b2be15sm1962333wru.103.2023.05.17.01.37.22
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 May 2023 01:37:23 -0700 (PDT)
Message-ID: <12704c8f-6727-62ec-d48b-31246755dbdd@redhat.com>
Date: Wed, 17 May 2023 10:37:22 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.11.0
Subject: Re: [PATCH v3 1/3] mm: Call arch_swap_restore() from do_swap_page()
To: "Huang, Ying" <ying.huang@intel.com>, Peter Collingbourne <pcc@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
 =?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
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
References: <20230517022115.3033604-1-pcc@google.com>
 <20230517022115.3033604-2-pcc@google.com>
 <87353v7hh1.fsf@yhuang6-desk2.ccr.corp.intel.com>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <87353v7hh1.fsf@yhuang6-desk2.ccr.corp.intel.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=g8h+buq4;
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

On 17.05.23 05:40, Huang, Ying wrote:
> Peter Collingbourne <pcc@google.com> writes:
>=20
>> Commit c145e0b47c77 ("mm: streamline COW logic in do_swap_page()") moved
>> the call to swap_free() before the call to set_pte_at(), which meant tha=
t
>> the MTE tags could end up being freed before set_pte_at() had a chance
>> to restore them. Fix it by adding a call to the arch_swap_restore() hook
>> before the call to swap_free().
>>
>> Signed-off-by: Peter Collingbourne <pcc@google.com>
>> Link: https://linux-review.googlesource.com/id/I6470efa669e8bd2f841049b8=
c61020c510678965
>> Cc: <stable@vger.kernel.org> # 6.1
>> Fixes: c145e0b47c77 ("mm: streamline COW logic in do_swap_page()")
>> Reported-by: Qun-wei Lin (=E6=9E=97=E7=BE=A4=E5=B4=B4) <Qun-wei.Lin@medi=
atek.com>
>> Closes: https://lore.kernel.org/all/5050805753ac469e8d727c797c2218a9d780=
d434.camel@mediatek.com/
>> ---
>> v2:
>> - Call arch_swap_restore() directly instead of via arch_do_swap_page()
>>
>>   mm/memory.c | 7 +++++++
>>   1 file changed, 7 insertions(+)
>>
>> diff --git a/mm/memory.c b/mm/memory.c
>> index f69fbc251198..fc25764016b3 100644
>> --- a/mm/memory.c
>> +++ b/mm/memory.c
>> @@ -3932,6 +3932,13 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
>>   		}
>>   	}
>>  =20
>> +	/*
>> +	 * Some architectures may have to restore extra metadata to the page
>> +	 * when reading from swap. This metadata may be indexed by swap entry
>> +	 * so this must be called before swap_free().
>> +	 */
>> +	arch_swap_restore(entry, folio);
>> +
>>   	/*
>>   	 * Remove the swap entry and conditionally try to free up the swapcac=
he.
>>   	 * We're already holding a reference on the page but haven't mapped i=
t
>=20
> Should you add
>=20
> Suggested-by: David Hildenbrand <david@redhat.com>
>=20
> for 1/3 and 2/3.

For 1/3, I think I rather only explained the problem in the first patch=20
and didn't really suggest this.

Acked-by: David Hildenbrand <david@redhat.com>

--=20
Thanks,

David / dhildenb

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/12704c8f-6727-62ec-d48b-31246755dbdd%40redhat.com.
