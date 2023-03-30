Return-Path: <kasan-dev+bncBCJ4XP7WSYHRBKFKS2QQMGQE4FKOTZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id B59E06D076B
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Mar 2023 15:56:57 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id t9-20020adfba49000000b002dd3986083bsf2019390wrg.12
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Mar 2023 06:56:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680184617; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fbolru64uojhzCpae81WeiwG+JzpdEL7BG0O78JfEopVGzip2gsPfNGs28ZOUImEsa
         FZi+1fivRiMAt7xiyfZG3Ug9c4nhidhmshVxGDz47CMKXilwntljGnBVV1tx5OkGOyvx
         IX8Y3pWoldoniNWus8gmaCd7MFnGMI0ACEFbfJKtsuqoN8CAMQvoW+UqR/kP+NeYzVSj
         1Wha2B5wzLjHAcgu9vXecxAXMSdKpEVIB0WeukRF3pp4nfH+qKg6ELi6kJavd0J4shg+
         wj/hhGv3oe2QVrEqq0Q5M7xm5cDpqkT21FfPwPsIjnd+FM23GvLEesiJNKJrTDrYfuWb
         tkjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=Re8KASy54NXDAWLqC59kT0XupO/bcGttwIgfBUQEmrQ=;
        b=HLeoFBLS6u8M3VGLfdDX5oCY9ujubqsBlQGGsIc1fBy8pk68l2z7RLet9CWXlc/NlF
         skILwHpQnrTpJ9ft4gizqJ7T1TxxkaUiyEnWsoY80UtxOckLoAaQN/E8hm9wKgKPFPaT
         GGKPSme4o2ClIOpOzZssPa8m5JczaTb+exuqX/hp/aZ3vAydGwHUvuM8FAmxa/kg9UHd
         pHe7qYab1tAqBhBVSoXimJAD8MoFCcaOlXzH/KWIe8RrahT8jkTQjBl7687YCP/nf68M
         1vLJombdUcDuIJRYY4nkCmSIvwxyFLIpFbrqX2NGxV2M01JcQIhv/GAG12QEJB9t7Jni
         YamA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of steven.price@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=steven.price@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680184617;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Re8KASy54NXDAWLqC59kT0XupO/bcGttwIgfBUQEmrQ=;
        b=W2lxFUSeogduNOF7HPuxSDXydkRGii3Br48ZHqFAW5EWfeTmNpspxwKuxvSXhCth8L
         jF23RZFt5UYChJYCAkJ2tk/tLk2uHntVA4Oy7QxHITbKwkZFi4fN8BKFFdOl1wytH9Hb
         6rYOWHJBjNE4fsWVOdnBCeTGSTGvWM0lf4a+jZuxEfAmIqSSbY3+tZvsLjuqgzgUepvu
         5OeFb1jeQX9owVobOlbCm5svlUddaoZDdRQM6/CvH1+XUqqkqKZzzSQ/1fuMD5QjiDAn
         Sha3BGzrq9BnV2uSavzJBk39C0HwZQfLizXTaYuZWFo2p0ZNZyd510DkmZinS0hRQXtD
         aX/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680184617;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Re8KASy54NXDAWLqC59kT0XupO/bcGttwIgfBUQEmrQ=;
        b=1JBGQ2T5iwqVYRtfDofJjBSGMj8x4uVgZYtAUYrQ2oaP8lo91bHqsbX8M7PL5nViHV
         9NA/76jJa01eu8lR4O+2O7hD7FTDdQPhECE52wT7ioM5QPqe9h6BlTTcNPyjGFSpnv9g
         cwrlxugLnATuXy3J5QreqE/uTfRMnpeMH7N4zqcmw61HJ96CDMfKXx8I0EQZiAzTSdqb
         X/o9/OPnlyzWdCRnnhkW+mx5vprpqQ8moeFTGB9NqZBFKSH3xwT7NyYyNUeu1cTEkYaf
         OCKun/YjPy8brpDmT77EHTLik54DVQErzzwSgsR8Ctc8p/maQpjsUk3kqUcm5b1NeMEU
         1xbQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9de8ZALTyhSiyYsttRh78SlQKNAwprQ5VzJqnPTceCcokO4EK0T
	zXplxeLHcJqul4aTqaL1x4Y=
X-Google-Smtp-Source: AKy350YYk89UeKcwndmXz0L0DxgzDlzqCVscMD2zWXIifGiUhAYltKKKdUaxNhoxPrvhmAxcEeIdOw==
X-Received: by 2002:a5d:4349:0:b0:2df:ebbe:7d46 with SMTP id u9-20020a5d4349000000b002dfebbe7d46mr2819690wrr.2.1680184617125;
        Thu, 30 Mar 2023 06:56:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1907:b0:3ed:c6c6:d96a with SMTP id
 j7-20020a05600c190700b003edc6c6d96als1079921wmq.3.-pod-control-gmail; Thu, 30
 Mar 2023 06:56:55 -0700 (PDT)
X-Received: by 2002:a1c:7919:0:b0:3ee:da1:1346 with SMTP id l25-20020a1c7919000000b003ee0da11346mr18736101wme.36.1680184615503;
        Thu, 30 Mar 2023 06:56:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680184615; cv=none;
        d=google.com; s=arc-20160816;
        b=u95hNpqTLLVBjnVeO7+Fe2cHACl8TYfF11yBKZVgfTGUU6XhQ5HzCBwACf/0kXv8hO
         0T414RdejpeXoh7gWQ8znt1O1130JmtOr3yXH1rnxwGIpYcMjLvjOfbzrN2I5KbvBSKm
         K2DvCV7WkDMItLnjKHlrDqRO/vJA86GbwfH+tL6jR5IZc1Es3jd9T0ffQXH2jQWQ+VOo
         EJO0A2RENm4Mx68IYeYPVUkhKClbULNRf2gKiWamxyv17c0CwBPGeUmbUEWU9abKomV8
         wSvBFnZ7Gy3JIoM5IOy+NPo4XkClpM2pM4vxNYbUeowW6A7OUq9PgUIM021u5kCPTaHs
         vz3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=Br1GY68qjJ0Wp1rtpij4lPP6LdlgTTBnhFV6CEdD1oc=;
        b=VGQ695thWaCSJgm+WuBsnKBAWflcHJUiVNVFMEZyXaDpV7MsX9t8Kb4q6TrKLBNNAX
         H2DDzUnj+owgy8EZSlLdOUAitzqrSR9Wqwyao80wdxs37PLX1OYRCm6NakRlRvguRUaQ
         6tNcDZHESysFPvYFnr6vsanukk4OgC9O6Wl36Gq+iEuKBNrfmmuJRCnTJ7TWqtuWudyJ
         F/cNfnHxnsBGaQ9hYUMCtkSgIHPhzv5q2muy3/3UOoySzKowITuHXbuPCu9GmnQ8UmMT
         AI2vqrzvYbdqvxU8oDpJOQH5oXmoQtk0jsbAOAkTPgVTml0s7egIOHcVyhJH7RqOoAi6
         SxoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of steven.price@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=steven.price@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id b4-20020a05600c4e0400b003ee1c61e7d9si457100wmq.3.2023.03.30.06.56.55
        for <kasan-dev@googlegroups.com>;
        Thu, 30 Mar 2023 06:56:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of steven.price@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id DC2632F4;
	Thu, 30 Mar 2023 06:57:38 -0700 (PDT)
Received: from [10.1.35.23] (e122027.cambridge.arm.com [10.1.35.23])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 6F77F3F663;
	Thu, 30 Mar 2023 06:56:52 -0700 (PDT)
Message-ID: <f468f934-40b6-3547-d3ea-88a0aac5bd6a@arm.com>
Date: Thu, 30 Mar 2023 14:56:50 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.8.0
Subject: Re: [BUG] Usersapce MTE error with allocation tag 0 when low on
 memory
To: Catalin Marinas <catalin.marinas@arm.com>,
 =?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>
Cc: "linux-arm-kernel@lists.infradead.org"
 <linux-arm-kernel@lists.infradead.org>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "surenb@google.com" <surenb@google.com>, "david@redhat.com"
 <david@redhat.com>, =?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?=
 <chinwen.chang@mediatek.com>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 =?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?=
 <Kuan-Ying.Lee@mediatek.com>, =?UTF-8?B?Q2FzcGVyIExpICjmnY7kuK3mpq4p?=
 <casper.li@mediatek.com>,
 "gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>
References: <5050805753ac469e8d727c797c2218a9d780d434.camel@mediatek.com>
 <ZCRtVW9Q0WOKEQVX@arm.com>
Content-Language: en-GB
From: Steven Price <steven.price@arm.com>
In-Reply-To: <ZCRtVW9Q0WOKEQVX@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: steven.price@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of steven.price@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=steven.price@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On 29/03/2023 17:54, Catalin Marinas wrote:
> + Steven Price who added the MTE swap support.
>=20
> On Wed, Mar 29, 2023 at 02:55:49AM +0000, Qun-wei Lin (=E6=9E=97=E7=BE=A4=
=E5=B4=B4) wrote:

<snip>

>>
>> Having compared the differences between Kernel-5.15 and Kernel-6.1,
>> We found the order of swap_free() and set_pte_at() is changed in
>> do_swap_page().
>>
>> When fault in, do_swap_page() will call swap_free() first:
>> do_swap_page() -> swap_free() -> __swap_entry_free() ->
>> free_swap_slot() -> swapcache_free_entries() -> swap_entry_free() ->
>> swap_range_free() -> arch_swap_invalidate_page() ->
>> mte_invalidate_tags_area() ->  mte_invalidate_tags() -> xa_erase()
>>
>> and then call set_pte_at():
>> do_swap_page() -> set_pte_at() -> __set_pte_at() -> mte_sync_tags() ->
>> mte_sync_page_tags() -> mte_restore_tags() -> xa_load()
>>
>> This means that the swap slot is invalidated before pte mapping, and
>> this will cause the mte tag in XArray to be released before tag
>> restore.

This analysis looks correct to me. The MTE swap code works on the
assumption that the set_pte_at() will restore the tags to the page
before the swap entry is removed. The reordering which has happened
since has broken this assumption and as you observed can cause the tags
to be unavailable by the time set_pte_at() is called.

>> After I moved swap_free() to the next line of set_pte_at(), the problem
>> is disappeared.
>>
>> We suspect that the following patches, which have changed the order, do
>> not consider the mte tag restoring in page fault flow:
>> https://lore.kernel.org/all/20220131162940.210846-5-david@redhat.com/

I'm not sure I entirely follow the reasoning in this patch, so I'm not
sure whether it's safe to just move swap_free() down to below
set_pte_at() or if that reintroduces the information leak.

I also wonder if sparc has a similar issue as the arch_do_swap()
callback is located next to set_pte_at().

>> Any suggestion is appreciated.

The other possibility is to add a(nother) callback for MTE in
arch_do_swap() that calls mte_restore_tags() on the page before the
swap_free() call rather than depending on the hook in set_pte_at().

Steve

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/f468f934-40b6-3547-d3ea-88a0aac5bd6a%40arm.com.
