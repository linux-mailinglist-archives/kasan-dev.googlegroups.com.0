Return-Path: <kasan-dev+bncBDQ27FVWWUFRBEVK43WQKGQEPWMYRVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 721A8E9CA2
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2019 14:50:12 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id h12sf1660110pgd.3
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Oct 2019 06:50:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572443411; cv=pass;
        d=google.com; s=arc-20160816;
        b=h3UNePoMwpUHscBMSs/MSryAKn3OXyMJKv0AmGVDxPmOoobpR0aG0rRLqhVK75/3CR
         vAd6azEjEo9S2vuh8MkwlyKguU/PfEcnLrd8rWYO1pIyPUXc+0vN8PI8f9XGvpFrN223
         9xxu723teMpzxihxEpLxcQ5zt8dUCUsURP/iw0q4eGowNYB4AO4Ax4gGio/KrRnFfdfj
         Ye40+wUPS/NLBBRrvpblyTt0E4xrqCrr0g+EmGOe507zhLiZ9H6Cp69alxtF6R1/lrwv
         DcaoVM7j40wBPnt889RAbS6V2/8oFklBYZ2tJWyMBPj8abrLLkTED7YTkcXMIK0ie0it
         CBAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=4ZCZec7IJxER+EEGWWV5mIs/OegmWNm2BNT9D6xDkvU=;
        b=ZFMKkjupTzvcU9RiBWg1hIQWxgyk/0kKmEwIJwEnuRkpp5dbpWWUMM/yBTyMuKhP/8
         IPO2P1o6dEsCRMQeeScvQ4/DXGkQdf396ZIblY2upzrYNy9XRQcjJ0uV11VLDs2WEsgV
         g/FROiQ611Iia7JKhkfNMwm7AD4uygcvntvEGrC8bztH0zNEGrevDK0P4zxI5zfZ0tBR
         5rJVMeMfsLUKomM/uWtIW+A/34EedbhMCsBxWXyHhyiOd7cPckoUAdFghJor229Tcrb0
         WVXftbObksQVlDO1vckBxUxiaK8qNr8ws9jPW6riNz6bvkz7izgAGFGO38osLKbIg24G
         EE/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=NTwARt8G;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4ZCZec7IJxER+EEGWWV5mIs/OegmWNm2BNT9D6xDkvU=;
        b=W+lbkPJBAADgSORpNRHubRNzrI8hA35JXpN9nCZ36PlHmUcftZzlpHybgBepZG89GJ
         zPWSGumXKPzRHq1kt0nZHwhIZ5u6CyBXjkeoYIn/zDOmoIuCsLtLvFrjtZAAzDtp/n0s
         VN5MCpsXx+7nCX3+jS5cWfST+Qa2pWYlwJ/i3y2Hlm8V8f+FfRYr42vy00QUmb6zV0Eb
         2lJSARTuqS8iTRuJ9NEofXMbCU37OBxGBDgcHH0sOMsnyz7XaAqwityuuT0m+0v1EIeE
         vDwvcHdM3TKw4vh7wvXbfRIP7HYwkBst3V6cp+ucQrK+dgYxsMSclCGBPHuFNRw4bYA8
         mXzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4ZCZec7IJxER+EEGWWV5mIs/OegmWNm2BNT9D6xDkvU=;
        b=TPtmlypqbB3yZGFBSb0UfnlDCpcIL2Jh/LJwycJwcWn34RemSdTzo9hx/xPNJeqzxE
         Bh+IQqf1ILb9rCGSLahWiw8u3co+oQGD/YzA5cPZn5stdbyX5nmweBzT5aHUXrhk0roy
         kcNRiUEFdMMKuTCluAwZqlwUAolvPfGiA5F+g8Dd3f2Jd7mUIfgxBkVBGeefYArywXmw
         U5Rx36mUCCEy4MrL7LTUO09UUa0zV7I5T/Qz5TY9/QULp0nJZbuZ+EDBKcaLaFgoKC7b
         gCy1FfRmyACWzEi6ckDY1s+6onTDnUcDlpAVRjd2C/N+wiLWomus9e7ENTRihZAx3ySz
         UsQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXebyAHZJmUYenRHH2ocTooqv+NCvNDcNqbZS5do0V8Q/HmsHub
	+H3Q7+TM0LOG1cBxrqIB2WM=
X-Google-Smtp-Source: APXvYqzeix7ZFfJU5Fl6G+98S6Z8H6RVUyfk30I6UkXrgK9O1fRQ8jApQnOO0P37XbVDf6PowtGQBA==
X-Received: by 2002:a17:902:1:: with SMTP id 1mr89694pla.338.1572443410561;
        Wed, 30 Oct 2019 06:50:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4b87:: with SMTP id t7ls7695490pgq.5.gmail; Wed, 30 Oct
 2019 06:50:10 -0700 (PDT)
X-Received: by 2002:a63:af1a:: with SMTP id w26mr34848446pge.251.1572443409886;
        Wed, 30 Oct 2019 06:50:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572443409; cv=none;
        d=google.com; s=arc-20160816;
        b=JEdZ/p+PsymRrUnTDYnfe2Q0FFiNZcpkFIoEegCnvqUJX86VuUHhOOLEKGJ25HyTTQ
         EHkP5Kzs7aXUJrsVj/Oou1mH6DNcj59oTK03yjapZQobTpPr0xjDZcKVF79vzyIA1mG2
         HxvTLVX3hGZbAe5r09KLjMg+M7WrrZZp2Lh8NpsDafSpumidHluwonIw71Pm4nRHCLbg
         ovrqQB1qp+BxGRB7+AVPv93yohxVITVpTih8CtdSoqLOSIQ74L7GcRSZJ7RH5Dx394TL
         EapBcTBPeo3vEJwWH5A5ZRwCkiiKqQaZSKrZe6GZnFuh8Y1rmkMGxbTx6pqWYlmsrT7v
         c2kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=pb0XrKghyFZgq2oeDgc1vRiv8K2ZCa6MKROaXA8DqHQ=;
        b=FQHj68NnmFGI//cZNMChLbwjMytIrD5FqRUKEpQa53UwKKT8dIESKAJpFDeuoCAozH
         ZLC5ac1CncOo03iDpdrfy+Xpr36WVZlI2/x6FWyrv6afzaJTtb+oW3066bmH8vGrJZ2d
         NEhxRnN6tEgt1Cpgaz7XvYiohJLQAnSODQY0+mHfBpAsyUElEH9dMYkx0OqYM2lgEWG2
         HsTOOj5trTZwLyr78n4+0vwnqD9c/xVqmaH3h6GX9y9fcfuOuTTrg6yIuZQrsQKbgfS+
         60pk9jVaLyGojlGI1exmxPeur7ozKaPoM2GK4CsFc0SW9ry9UtyHro5EO3ISXalEGbGF
         P5NA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=NTwARt8G;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id az24si391770pjb.0.2019.10.30.06.50.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Oct 2019 06:50:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id k7so1033835pll.1
        for <kasan-dev@googlegroups.com>; Wed, 30 Oct 2019 06:50:09 -0700 (PDT)
X-Received: by 2002:a17:902:760c:: with SMTP id k12mr102582pll.256.1572443409483;
        Wed, 30 Oct 2019 06:50:09 -0700 (PDT)
Received: from localhost (2001-44b8-1113-6700-783a-2bb9-f7cb-7c3c.static.ipv6.internode.on.net. [2001:44b8:1113:6700:783a:2bb9:f7cb:7c3c])
        by smtp.gmail.com with ESMTPSA id e198sm35049pfh.83.2019.10.30.06.50.07
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Oct 2019 06:50:08 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org, glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org, mark.rutland@arm.com, dvyukov@google.com, christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com, Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH v10 4/5] x86/kasan: support KASAN_VMALLOC
In-Reply-To: <a144eaca-d7e1-1a18-5975-bd0bfdb9450e@virtuozzo.com>
References: <20191029042059.28541-1-dja@axtens.net> <20191029042059.28541-5-dja@axtens.net> <a144eaca-d7e1-1a18-5975-bd0bfdb9450e@virtuozzo.com>
Date: Thu, 31 Oct 2019 00:50:05 +1100
Message-ID: <87sgnamjg2.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=NTwARt8G;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Andrey Ryabinin <aryabinin@virtuozzo.com> writes:

> On 10/29/19 7:20 AM, Daniel Axtens wrote:
>> In the case where KASAN directly allocates memory to back vmalloc
>> space, don't map the early shadow page over it.
>> 
>> We prepopulate pgds/p4ds for the range that would otherwise be empty.
>> This is required to get it synced to hardware on boot, allowing the
>> lower levels of the page tables to be filled dynamically.
>> 
>> Acked-by: Dmitry Vyukov <dvyukov@google.com>
>> Signed-off-by: Daniel Axtens <dja@axtens.net>
>> 
>> ---
>
>> +static void __init kasan_shallow_populate_pgds(void *start, void *end)
>> +{
>> +	unsigned long addr, next;
>> +	pgd_t *pgd;
>> +	void *p;
>> +	int nid = early_pfn_to_nid((unsigned long)start);
>
> This doesn't make sense. start is not even a pfn. With linear mapping 
> we try to identify nid to have the shadow on the same node as memory. But 
> in this case we don't have memory or the corresponding shadow (yet),
> we only install pgd/p4d.
> I guess we could just use NUMA_NO_NODE.

Ah wow, that's quite the clanger on my part.

There are a couple of other invocations of early_pfn_to_nid in that file
that use an address directly, but at least they reference actual memory.
I'll send a separate patch to fix those up.

> The rest looks ok, so with that fixed:
>
> Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>

Thanks heaps! I've fixed up the nit you identifed in the first patch,
and I agree that the last patch probably isn't needed. I'll respin the
series shortly.

Regards,
Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87sgnamjg2.fsf%40dja-thinkpad.axtens.net.
