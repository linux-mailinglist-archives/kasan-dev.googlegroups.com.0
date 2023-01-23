Return-Path: <kasan-dev+bncBDUNBGN3R4KRBLN5XKPAMGQEDAZ33UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id DAC0E677E63
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 15:50:21 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 9-20020a05600c228900b003daf72fc827sf7604274wmf.9
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 06:50:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674485421; cv=pass;
        d=google.com; s=arc-20160816;
        b=JFFNGi9yhs/39X4o80uOgBDPp1u9wS3/NBgWjhQzWdUVDs586GVO7xHpBOWCw/dw4B
         Lngs+2Iwgvo3KkrJLUztCs70s9IAP8ziHv8MXAatqGy9bNyx2gqZKBoxHC2SgCIQADf7
         ZBk9G0ku+ehFaMXFkG9n4y6zP0pF2zv7C4ZWhLapFb7UuCw8NkLarwZEX/iqZb+RpH75
         7VKAdrQb+GtGRQnCHyyCl73aEcXC89VN7JVyBCM0HEKoQFVmkbsBv0ZFkYui/zyy1tMC
         5kbid82Fm19ZAd856TY3sBtcWWd7pgV/Cj8VU8yfF/uI4mHBfCbtxqw7rvoRumVm71Gu
         nJfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=GyFms0fn9PzI+GX8OMqgAUaQ/5NRdnbSreh57Ra3Kxk=;
        b=hRhIF0TSWdwrjvRvi0D0+rcbzqbVZEVvPmVM5JYSOo+tPgyyjb/5SJSRqk08jkr7me
         yXg8qG8BdYA29PH9NVI9Us3z5m2J/mna+NCkfbwGDE0xS5CAWRXuTBfkKEW8A+mTbl1M
         V/9Ol5ZGsUDD4e5m6B9D+SgSUm0DfWfFBIMR6LDRvIA2ZGX8wMekAxCjErPa9WnPkHp7
         fJuRopdAeqUDTr+w8HP+DV/jgD8DO2WTI5JsBxzv5yeeUQG3BgnUujJueVyTxJs/zxrb
         GHAYhZ6Di6dEo/TNydDrS4YwOwrUz3H9RnnO3MB2jKwwBrK7oY+0lYsmOKs3Sqzkqf7E
         NJww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=none (google.com: lst.de does not designate permitted sender hosts) smtp.mailfrom=hch@lst.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=GyFms0fn9PzI+GX8OMqgAUaQ/5NRdnbSreh57Ra3Kxk=;
        b=Ngdu/r+sJc3M2Ws7efNFez2qWpAnAP5wLKvFqpP0XcAlKEQmpKUTpckznlv7nJ33sV
         JRc4dloi+kFWBvECkou2YgKQmF3L2H73Sof+phj8pveZL5pprWJZ36ZUihmGGQmP9DLe
         XSv6YCD6fNkvGcWES2A50J4AgagbHQFS1KUjtc8RJph7WjHARlkQciKSA44Ht3+5t4ZN
         A7SgqFweVdYw0BiKayUI88ZXcrQ+TqHn802yf15wyaLfxqVJeHzZtsoMg8ZXbAtM2Bfl
         0kvWKpQrflB+qtNjL5t1HjGTdzS8nNrhJatpDHgki2NgohBLclUp5T7QTlhhyhszmeeU
         /m2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=GyFms0fn9PzI+GX8OMqgAUaQ/5NRdnbSreh57Ra3Kxk=;
        b=Juc8szXGWnxXlpRNYQ/u9kzB/OZ+X8cS/BMM8r0Yav/HGPPL3G+NWDQMSCdvsUEYwH
         0Cy8IcKPVLYBDDm0SyZGtlGN8U76Z5Fiu5+v64OFK+x4VtCfl5wWoXY5MW3Lit7CquqC
         NM+dbbssKSBsDMceilx0VJGhkKBPDxnJwKe3HAzI4FjHGviuazAsWsthBFHX9/AUVdMn
         0MdzDuppaGit1lySWGO0l3QgUM4s59iskG/v+4IW/VkNrKCiW6KLA0pZ1VA92INtgKlF
         0q/1+pfwUhc0FId6ohGkPlY9LpApz9l+gmyflPtGsuqXIJBTR6BsWyAON0c7o2U4ABXH
         /5Ag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koAQaozS7HphbsZwMpQJ+fRzlon/+fvAVXGcO72+vULEIn2Fp9A
	0avfpBAyig5mJw1Bsij42VY=
X-Google-Smtp-Source: AMrXdXt8Lzt4S4ZPDXa14setprywy9rMQo1SRuQYgntN9r0WM0rtgrLoYjJihWCfK6hHUcXc+WJrzg==
X-Received: by 2002:a1c:f711:0:b0:3d1:e3ba:3bb6 with SMTP id v17-20020a1cf711000000b003d1e3ba3bb6mr1423147wmh.29.1674485421401;
        Mon, 23 Jan 2023 06:50:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:2cc4:b0:3da:f543:3b48 with SMTP id
 l4-20020a05600c2cc400b003daf5433b48ls2626925wmc.1.-pod-preprod-gmail; Mon, 23
 Jan 2023 06:50:20 -0800 (PST)
X-Received: by 2002:a05:600c:1d10:b0:3d3:58d1:2588 with SMTP id l16-20020a05600c1d1000b003d358d12588mr21125481wms.41.1674485420237;
        Mon, 23 Jan 2023 06:50:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674485420; cv=none;
        d=google.com; s=arc-20160816;
        b=vRy5GYq5CggmEULFSiPFFMTKuPgU3Byxwda9PLd9XI4o8ihsEU8Ym76BiMbOb2pVUB
         devSxYIT0FUiPZK0Xgl9rV7IaKdMPTQDR9M2n7Ln9/s7W4AuNmVMAK6c01/XqTtugxwQ
         Y2Td42umvtFFU8fqXAG/yEMiNOmx0HEQga2Shc8vHUAGDs9N2z5sBApmRpZeJ1mFXQb2
         h1jnKxmmmpZWxDavylhdC8XPjk5qyTUUELu4z2oHXhGO7MIDehJ5W1fGpHJERpjMHWHL
         VN2M23UP92wOx7Kl9ljBGs1CNXHcScw0X4r7nV5rS2LOHW+BMEi1ZSZazAkfhczC1kFK
         +fTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=5DZKS4NnWojlLCM5gl6FbhPLtm469wVljSa2U7EFRyg=;
        b=sgjjIEOMh1+iVNnYz0TzlBG5YjSROzacev86Z57bnqviaay8bEkxH1AklDX26UINvx
         pdqgnJuQBf6hZf7FcsGKFVWB4OZOGMQE+XWmYknUZZX7r3HmPUqoO5Uuzf/8d3WCfmzu
         FiXNTPflcZHoQFQUpqKVLqK0XF+fiSiKYtrqD6ibCRL4btqp9nUf+XLMB969oILPNR8E
         0NIIsqtGCp180TGqmu2o+Qy4txnPCiCFW30zXHVcCcR8tWjzous5vZpTYon3yOMvdwHK
         glmd7wbSv6H9p7/DirXsnfguXAL08A95fFH9/Dd3rZdA5T0CGnTosCZ2BfS1FDOGrFOZ
         WEwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=none (google.com: lst.de does not designate permitted sender hosts) smtp.mailfrom=hch@lst.de
Received: from verein.lst.de (verein.lst.de. [213.95.11.211])
        by gmr-mx.google.com with ESMTPS id co6-20020a0560000a0600b0024222ed1370si251180wrb.3.2023.01.23.06.50.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 23 Jan 2023 06:50:20 -0800 (PST)
Received-SPF: none (google.com: lst.de does not designate permitted sender hosts) client-ip=213.95.11.211;
Received: by verein.lst.de (Postfix, from userid 2407)
	id 35D0268CFE; Mon, 23 Jan 2023 15:50:17 +0100 (CET)
Date: Mon, 23 Jan 2023 15:50:16 +0100
From: Christoph Hellwig <hch@lst.de>
To: David Hildenbrand <david@redhat.com>
Cc: Christoph Hellwig <hch@lst.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Subject: Re: [PATCH 08/10] mm: move debug checks from __vunmap to
 remove_vm_area
Message-ID: <20230123145016.GA31543@lst.de>
References: <20230121071051.1143058-1-hch@lst.de> <20230121071051.1143058-9-hch@lst.de> <02bc3d67-3457-ff17-0810-e75555609873@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <02bc3d67-3457-ff17-0810-e75555609873@redhat.com>
User-Agent: Mutt/1.5.17 (2007-11-01)
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=none
 (google.com: lst.de does not designate permitted sender hosts) smtp.mailfrom=hch@lst.de
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

On Mon, Jan 23, 2023 at 11:43:31AM +0100, David Hildenbrand wrote:
>> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
>> index 97156eab6fe581..5b432508319a4f 100644
>> --- a/mm/vmalloc.c
>> +++ b/mm/vmalloc.c
>> @@ -2588,11 +2588,20 @@ struct vm_struct *remove_vm_area(const void *addr)
>>     	might_sleep();
>>   +	if (WARN(!PAGE_ALIGNED(addr), "Trying to vfree() bad address (%p)\n",
>> +			addr))
>> +		return NULL;
>
> While at it, might want to use WARN_ONCE() instead.

One thing at a time.  But yes, this makes sense and could be an
incremental patch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230123145016.GA31543%40lst.de.
