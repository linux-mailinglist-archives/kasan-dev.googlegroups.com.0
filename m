Return-Path: <kasan-dev+bncBAABBVNNQDYQKGQE4LOCKVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id D54ED13D56B
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 08:55:01 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id dd24sf13302025edb.1
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 23:55:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579161301; cv=pass;
        d=google.com; s=arc-20160816;
        b=hJd0xiUSVE3M6Wv71zkuza0Nj5cIbEE/jbUk/9AaXACDGCHu9q5IVC3pZPw07Ugvmo
         svo+AX4NJXsp6qorl0L36fZSn9P3fmIFjjIBQGi50uaGzbv1yCMEICg91CeR33Q6tXCV
         GtZoLL6+Ek0mRFoNTKPU8L0LVSbOIOrw8bqlbwq3nC5uhUou4zw0rHOaIWW52ltGIW/6
         YcmuA3REpr0EWL7e9PG/HtqRl7jTFoPxJAxcPQfLl2bUONTebTVtP7PqEFpdFsG4izKd
         YL6lWN7Fu2e0M9sljiPIL90Y+NN2IREbPqz93s5BteuNUFjDLIeqIyFxHAmPqWN7PDbc
         t9lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=08xvuSbgDv8dpRpMtb0a1cWXtpBk+9A5w3FZbnP7mR0=;
        b=O7x9sOBvFDkYPBl1mnkgQHY9gAvmAPeoVuKpdS3MUydTElPx3qocLLNgj6V0HM17J+
         R4DeaWzqEN7Pvq4UPVJt3aLCLodxK4OYzNEcyW9I4p5ASq8qpHT3QTrxR+yo28O6HiSb
         QoOKBzIz94C9sztGp9c3d1Lm8lwL+esteKbwbgNLi8f8cDvEAHZEJvZUWpCYcvB6QndB
         kDFawsy5lrNmznHkCUQb3AyHQzZX/WOEXllABk/ZLqvSDeZVHmwTKmc0MoG0iTfI6k43
         nq6frZBeWQaLImaD21zeotEED2p//MepuEuwuJHP+NftikwW2z1gA7VEKtAA7XF8pywE
         7EBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=08xvuSbgDv8dpRpMtb0a1cWXtpBk+9A5w3FZbnP7mR0=;
        b=Vtx9BXqthAAyunHo0YXipbs9yKB4kh8C7wZ/t7RK7VyHimltUi8ntcLwgx44DSs7NH
         vPIJr3w/Xyp1TcKjkNdA4qmhLqK0GZazHCiTOV1UIrd57CaMXlAEaaFg8FhRhmz/b8YY
         tPzpa9pgvFYmcjF6zF9spEn9dpqm/30bX1i+R/3/SyqWH1vNt2szYumCpmRC05PWP6t+
         4tj+a4NELbaRB58sI+WoZ+hAOJD7qRpsHcKiqTM5qB/tXxqEcdNHa+l6ESuZ6Ux3FGx3
         9xUhtkyIsYbKyRP4JkP93E4SIQ/08lfFleY6VbStBiUuzrGc0sRBdMJKWswIV8isqTCD
         iIfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=08xvuSbgDv8dpRpMtb0a1cWXtpBk+9A5w3FZbnP7mR0=;
        b=GhyZAD88vMaeqnnuP8GsOBPiu2SLfEe+u6EQ5PnAw25Ob8ne+otvQ3qQzakCZzttkZ
         1vN3DDoboGFMOY4bvVp4Q+koNoB7n9F6DzJbT3/3PV02zstFRNtaLRTywjrfW/ZEgeYk
         K9NW42kViHyTPrxBJH2EnuSGwCp966bQgFzEAYEF7tCNE69R5LV9HFngjrLf2OHoqRr1
         FqDroHmlAR4e6WiY2fjtZZ7daetAeSV8DGQF076xMbFvUo7WCCISe+FASww9mkp+pxwS
         FUgneO240qvOZeP2LhD8JG6Twf0+3GCfDcB17+fA2yBumpHXyemseovAT7vgBjh+p69U
         j6iA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUDL3qaUNr7nTmOPI58kxQ4wVg5MQzwslOcXhGq7iLWis/vYwLV
	GFCTLVnbG4Fcu5SW/np1y1M=
X-Google-Smtp-Source: APXvYqw7f9dfgHCKt92f8Pz6NcEb3l6ILftkUwiC9EKqgvAaetcR2C3Qsn7HCRZQYnAxpwK/Vq1qTA==
X-Received: by 2002:a17:906:ed1:: with SMTP id u17mr1589951eji.286.1579161301314;
        Wed, 15 Jan 2020 23:55:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:897:: with SMTP id e23ls4916824edy.12.gmail; Wed,
 15 Jan 2020 23:55:00 -0800 (PST)
X-Received: by 2002:aa7:c2da:: with SMTP id m26mr35639245edp.244.1579161300957;
        Wed, 15 Jan 2020 23:55:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579161300; cv=none;
        d=google.com; s=arc-20160816;
        b=u8+b/8wodUzeJRrJtvx3FiDD+huZl1D0OCi1Btbfvp43tdRuuy1fMAFEWODsXXkjhO
         3QIeAWuhocSNrjg4kuO7s7+QlBT0zLdXxX7NvzJyRoXRXVN6MdizKPnjLABPQGj7hoif
         PfaAmim/D74oWpljWxwL7vQZHjTQcTzdDXnqq3fSXYcWIYuSCtDn6apMPbJwkH7rFWUx
         OqjaYhJI+pVS2mgabfT6jy/Ftt/5rCU8D5MfdVXEmaWItKOhzdtVbFyzxh/78j5JVpcO
         c0siF8vDGotTMOcGdFieAYkhOY6iUSoGgkYuX5xgT2u9nY97a8qkqTMVsH9jZWtzGQ/E
         FC9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=sK+xxYhIGWS8mM1bV0s2HiVqedY3pD3W9xWs5yqSwu8=;
        b=XoVBSz6iPMZQNI0J/fMvzAVMn5Ze/JSEUaWFc1+UuDg/06NY/MuMEvp47u8a0rJw6C
         goQtdKBDlEPCoPt7xywEYX1x8IG/RDQKZCM7QJJMKEWTOmz12SycsIqxwZXOqO1TduXJ
         PG30tuDiCR+Vj+QgPwXMSK9i51L2fO7T7ww9tEFRYgHShxJZ/oocPjs/pxufxzoCPum+
         Trn8/swlRownlFNd7mRC0gc77hQUaqb39DRS86mTtJMn0fffR/2HhRId8LsBG5UPEkB1
         Yi7GmbRH4dIjJmczUoTdCeFo6+aXxtEPl7tLrxJsn8uqlJ+swqhrJSchtVh0nHRp70Qv
         Bm0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id x18si910292eds.2.2020.01.15.23.55.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Jan 2020 23:55:00 -0800 (PST)
Received-SPF: pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay1.suse.de (unknown [195.135.220.254])
	by mx2.suse.de (Postfix) with ESMTP id 4D021AC2C;
	Thu, 16 Jan 2020 07:55:00 +0000 (UTC)
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
 <6f643816-a7dc-f3bb-d521-b6ac104918d6@suse.com>
 <c116cc6c-c56c-13a5-6dce-ecbb9cf80b3a@citrix.com>
From: =?UTF-8?B?SsO8cmdlbiBHcm/Dnw==?= <jgross@suse.com>
Message-ID: <c0e6f3a8-85b1-ba92-7379-bdf5f1225ff5@suse.com>
Date: Thu, 16 Jan 2020 08:54:59 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.1
MIME-Version: 1.0
In-Reply-To: <c116cc6c-c56c-13a5-6dce-ecbb9cf80b3a@citrix.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
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

On 15.01.20 17:32, Sergey Dyasli wrote:
> On 15/01/2020 11:09, J=C3=BCrgen Gro=C3=9F wrote:
>> On 15.01.20 11:54, Sergey Dyasli wrote:
>>> Hi Juergen,
>>>
>>> On 08/01/2020 15:20, Sergey Dyasli wrote:
>>>> It is incorrect to call pmd_populate_kernel() multiple times for the
>>>> same page table. Xen notices it during kasan_populate_early_shadow():
>>>>
>>>>       (XEN) mm.c:3222:d155v0 mfn 3704b already pinned
>>>>
>>>> This happens for kasan_early_shadow_pte when USE_SPLIT_PTE_PTLOCKS is
>>>> enabled. Fix this by introducing set_pmd_early_shadow() which calls
>>>> pmd_populate_kernel() only once and uses set_pmd() afterwards.
>>>>
>>>> Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
>>>
>>> Looks like the plan to use set_pmd() directly has failed: it's an
>>> arch-specific function and can't be used in arch-independent code
>>> (as kbuild test robot has proven).
>>>
>>> Do you see any way out of this other than disabling SPLIT_PTE_PTLOCKS
>>> for PV KASAN?
>>
>> Change set_pmd_early_shadow() like the following:
>>
>> #ifdef CONFIG_XEN_PV
>> static inline void set_pmd_early_shadow(pmd_t *pmd, pte_t *early_shadow)
>> {
>>      static bool pmd_populated =3D false;
>>
>>      if (likely(pmd_populated)) {
>>          set_pmd(pmd, __pmd(__pa(early_shadow) | _PAGE_TABLE));
>>      } else {
>>          pmd_populate_kernel(&init_mm, pmd, early_shadow);
>>          pmd_populated =3D true;
>>      }
>> }
>> #else
>> static inline void set_pmd_early_shadow(pmd_t *pmd, pte_t *early_shadow)
>> {
>>      pmd_populate_kernel(&init_mm, pmd, early_shadow);
>> }
>> #endif
>>
>> ... and move it to include/xen/xen-ops.h and call it with
>> lm_alias(kasan_early_shadow_pte) as the second parameter.
>=20
> Your suggestion to use ifdef is really good, especially now when I
> figured out that CONFIG_XEN_PV implies X86. But I don't like the idea
> of kasan code calling a non-empty function from xen-ops.h when
> CONFIG_XEN_PV is not defined. I'd prefer to keep set_pmd_early_shadow()
> in mm/kasan/init.c with the suggested ifdef.

Fine with me.


Juergen

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/c0e6f3a8-85b1-ba92-7379-bdf5f1225ff5%40suse.com.
