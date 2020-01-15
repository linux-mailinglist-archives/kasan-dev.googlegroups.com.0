Return-Path: <kasan-dev+bncBAABBAPG7PYAKGQEJKYQW5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 831DA13BE2C
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 12:09:53 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id j4sf7848301wrs.13
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 03:09:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579086593; cv=pass;
        d=google.com; s=arc-20160816;
        b=FcTlieBuVAe6Q9gplvAkT9fvzluTH9NxZ8GstxKzLznVTfqofw529wFXriBNHF2c+U
         LuaiZMnEIH1m/syAqc9+zRUxck58mclAmvUXt8QADerDxqpcwxmSszrJGWF3H0ZvaqgT
         Jl0Z34FkYErqvb7aQs/N5yO6loYA3EqfZRsdEi2A7RvR0a3lBb21fLuDAnbMQkGNdxv9
         n+8++SwaPj0DRjVPvi9XIVTX6m/TbgjaZciLGd5hXKs8Yv8djwoXEs6q0iBVsbMeNDQC
         EdJNjnohZwgbCGzVtC1Xt2Yb7xyo5yWPFtbbhGW0YXhQdVWMaWCqCbr/DcYNyQ9wTNut
         btDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=opL7ErlITLLsRzkeq38yGUPPQJRQFuVGW+H83uZg+fw=;
        b=B0u0vE7QaFVUk0AhV6XP+glql6Npx8MaD8uxq8GnMs38/xCF5tDyomVRwod0aM5B01
         fQj/JGbRJTfi0LoF9ZmQSydqjpN87cqvl0KEvZ/6vIftwniZbc0VrQJUcgY1n0dvnauG
         S4eOvXJWS9OrtTwwWmY7wGqLZslX3DwcmU8tr2vRrQXt+F5/HCN45npmOLVIsBKencIl
         3hLomPtGFqqoel7rkuubnkehTWlWdsHsFGlEd1oReKCtq1+CRyHRbOEc+8rWqXbg690D
         3swM/4Zf4i/BHSu3HfS0lJVl1wYB5XOKum4otSdyCxA1usyEfuiR5biuZivCswVFTutd
         khGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=opL7ErlITLLsRzkeq38yGUPPQJRQFuVGW+H83uZg+fw=;
        b=ZpTn725gJ2LULuTr5I7sZPMS5EhFlGiV6vX5PPVCtzOYOph9OGblcZMRLds78UF7X/
         xh7KM8iLfSfAyfmdfsfqYVkTDAo/ULjrQArw4GzmmYPqE3A/o/DYmf/LXIx44nWdlloT
         0N0HlP7aRkPH1vfWapeml9ad3x7grD1IHo0lHnYQK0H/MOcX1gTKd2pXUGFDcRNH4lVA
         8lG/oFrxv1YXWzM9M1sxLb2Z2TOtcanxVtjO2VFMTTWW+PtVPh1H65VHwVrq9DIQOkUl
         2DrBdNAijcXC6/HG6KbpS0HavFH8OXvx0vVBGRLZts4Iht+AQrgdpsWEedFIUpMtMNXO
         BdAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=opL7ErlITLLsRzkeq38yGUPPQJRQFuVGW+H83uZg+fw=;
        b=f1XDzRRWOTiS6pv6Yf/r7V0reZv2v1uMI9kfZbT43vk2MWCC4fi7JOn7Z5XphV5iED
         tEbl5F2WfEh145iXEtMQEgqfQWNfmJkiHK36jXXkXB6yJfxi+h6h7mdLXN+Q/8A+o3nu
         IcWOBEWDAmcW6bLs3XjnCci399tCh2huWlKtaakLxVAYhNFWNJFWIuWvlLz09qwFltqY
         JfPUa6YMpy/FlD85YVa3Mr1c5fNyS2bZWBqe6134E7K2JTcCEwZyILhqHc95nP8GguVg
         WS7Ps3YWfWMntHwlh7Qp/rb+pR6DDBt8QWvl23Oo4x3IzNEmC8Pzpzu+4Dp4EnfQkbdN
         Wnfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXFpsqChqq5Bbt+c1N+N2o4/7AAIELh9oMhpQIwCA/MrNSTH0jh
	sNV1aomjCdsWC+Twlih7lwc=
X-Google-Smtp-Source: APXvYqw2xvk2SWk7WfY24MTxxOaCQWIjUKfgfPzzPS3HnjplIk9deYSv4Kr9tNqVr/HvUAd6fJu6Vw==
X-Received: by 2002:adf:82e7:: with SMTP id 94mr31036687wrc.60.1579086593069;
        Wed, 15 Jan 2020 03:09:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ea84:: with SMTP id s4ls6721592wrm.11.gmail; Wed, 15 Jan
 2020 03:09:52 -0800 (PST)
X-Received: by 2002:adf:fd91:: with SMTP id d17mr32178438wrr.340.1579086592724;
        Wed, 15 Jan 2020 03:09:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579086592; cv=none;
        d=google.com; s=arc-20160816;
        b=jQlz/b3UUlNw1Eg55HQ3J3zV4bjPqXu24+nZuA9CqdMMHlvC6Ug7nAaxJMZ2xUu07+
         u0no60hXthGT1/EgkGmfvh6Sk/u8cGpV9zrWfnXrUwf/bpWzkPHIcExwm5cuLDmRu80k
         QrRcLjKmvR1W+m/n3mvIagJQOTaGjlKqaLIZujairtNYe8arAA+lYNo14YmyPuqOcGkk
         dBe8Jpl17NL+Nq+6fxU+V7xHJ8R8KRgpSnXstqblcnmQ8LIcSNRzbUI7sh1huidsyHe2
         5p1jbWkU7KMHj1cj0Fc4tD6KMjVNiv87/ta1HXolAunY2cJYAwnSnUeZdwzVN4dFXG++
         M4fA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=8Nar2xDuEvZwmTGfCQ+vV9tKxi5k2aRSad6YbGSEUVI=;
        b=MibggB7CFyKjPLwcEMWFW5K6hYi7FqdZAOAn6Z54jy3y3yVysAlB2bSXXBlwTrIP+A
         1ahnmKh4Rpy049EXAXIahbIphBvQhyav7PxHnbgIsgk/Dv5rkFqjPFFzc4fApNGXmvfr
         ZL2sVnykvIiuYZb84Kz1BtdBtofqxNDE4DNIHM4tbqzS4vK+WL672CSD0KSkFjTq7knp
         24mQEuDFrEKdtehODHTwfT+7ZHXuSJLL78nM8pZE2sQcDK5hBDl6KtDuFsM3s3M6IkuM
         QEBsEFSJ5c4grxq62ikgGn//MkcF+FClqOiq1Cy+h8hFj6OjDDwVHthk5VwWM+hsh6Yy
         huRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id u9si674080wri.3.2020.01.15.03.09.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Jan 2020 03:09:52 -0800 (PST)
Received-SPF: pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx2.suse.de (Postfix) with ESMTP id BAB13AC81;
	Wed, 15 Jan 2020 11:09:51 +0000 (UTC)
Subject: Re: [PATCH v1 1/4] kasan: introduce set_pmd_early_shadow()
To: Sergey Dyasli <sergey.dyasli@citrix.com>
Cc: xen-devel@lists.xen.org, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Boris Ostrovsky <boris.ostrovsky@oracle.com>,
 Stefano Stabellini <sstabellini@kernel.org>,
 George Dunlap <george.dunlap@citrix.com>,
 Ross Lagerwall <ross.lagerwall@citrix.com>,
 Andrew Morton <akpm@linux-foundation.org>
References: <20200108152100.7630-1-sergey.dyasli@citrix.com>
 <20200108152100.7630-2-sergey.dyasli@citrix.com>
 <96c2414e-91fb-5a28-44bc-e30d2daabec5@citrix.com>
From: =?UTF-8?B?SsO8cmdlbiBHcm/Dnw==?= <jgross@suse.com>
Message-ID: <6f643816-a7dc-f3bb-d521-b6ac104918d6@suse.com>
Date: Wed, 15 Jan 2020 12:09:50 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.1
MIME-Version: 1.0
In-Reply-To: <96c2414e-91fb-5a28-44bc-e30d2daabec5@citrix.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: jgross@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=jgross@suse.com
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

On 15.01.20 11:54, Sergey Dyasli wrote:
> Hi Juergen,
> 
> On 08/01/2020 15:20, Sergey Dyasli wrote:
>> It is incorrect to call pmd_populate_kernel() multiple times for the
>> same page table. Xen notices it during kasan_populate_early_shadow():
>>
>>      (XEN) mm.c:3222:d155v0 mfn 3704b already pinned
>>
>> This happens for kasan_early_shadow_pte when USE_SPLIT_PTE_PTLOCKS is
>> enabled. Fix this by introducing set_pmd_early_shadow() which calls
>> pmd_populate_kernel() only once and uses set_pmd() afterwards.
>>
>> Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
> 
> Looks like the plan to use set_pmd() directly has failed: it's an
> arch-specific function and can't be used in arch-independent code
> (as kbuild test robot has proven).
> 
> Do you see any way out of this other than disabling SPLIT_PTE_PTLOCKS
> for PV KASAN?

Change set_pmd_early_shadow() like the following:

#ifdef CONFIG_XEN_PV
static inline void set_pmd_early_shadow(pmd_t *pmd, pte_t *early_shadow)
{
	static bool pmd_populated = false;

	if (likely(pmd_populated)) {
		set_pmd(pmd, __pmd(__pa(early_shadow) | _PAGE_TABLE));
	} else {
		pmd_populate_kernel(&init_mm, pmd, early_shadow);
		pmd_populated = true;
	}
}
#else
static inline void set_pmd_early_shadow(pmd_t *pmd, pte_t *early_shadow)
{
	pmd_populate_kernel(&init_mm, pmd, early_shadow);
}
#endif

... and move it to include/xen/xen-ops.h and call it with
lm_alias(kasan_early_shadow_pte) as the second parameter.


Juergen

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6f643816-a7dc-f3bb-d521-b6ac104918d6%40suse.com.
