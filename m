Return-Path: <kasan-dev+bncBAABB7G4UDYQKGQEKRWYGGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id DA6F114537B
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Jan 2020 12:14:04 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 18sf1896793wmp.0
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Jan 2020 03:14:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579691644; cv=pass;
        d=google.com; s=arc-20160816;
        b=LL38IQjMZiozbzHnFhDWm/+pgGHofNJdhsJh/fqw6oFZGkaV7n8SGHtdpvHr1WfZ67
         3ruQ7mUmxELCJIdVpSdrgllg0iQe9xEgMytOgJ/Jbt+Iwb8zowuSYOhFK5ZjvVlWIRsi
         aY+5oi2YvkXs6Pq3nLZq6BhZa3ijxgC4eazK+soky8fYEPubHY6qWqB/JjwzUvuRNLrJ
         bWBCZS7m0+X41jGX+vQzUBh+8gREnSVgDHHEyuVw3u7OGXqcgyByuSXs9inlIcdI08zF
         4oXtCHGpfWlg2bJdYllBM/tTZmOD10YoSu4QL6wCZBImv+3xaMccn3YJH9tU0b87Qvxu
         Yyjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:ironport-sdr:sender:dkim-signature;
        bh=aJ6gqDclJps+92yMi2EqP2zs5MKmSwUtrEDcizFcW3Q=;
        b=I18LfwnVtbiBdmBW6bflcwrmwczEXyTzzjFciNVOQRitbWVm4gC0XUEH2GxCTtg8Lj
         l5cylpvenAQW1Z72zHFl5Hxp3ZizLBr1RVUhUzgPDcTZMg6WCtQJ8oSM82/TAWfeHrIS
         PFl0hcR1G+pFeZcS2Y5emK6b86iAqy35ezlIBpCLAbk/DN4EsZWs/qsDzS9NGPVlKVJ2
         +Y2HnJPH7NQnxi2ffbPBosQ7Sk+ZXLLDyzJ/3bEfxxv4FGFOS0rAKFxSMFv08WAIzKKh
         w/6cSjwtC3FxWX/kzNZmTliwrPsUD3lCDC1Ag4nTcgQZaWLvDrok5ZecrhC6U0wve2Jc
         CEBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=VekwyUgO;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.144 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:subject:to:cc:references:from:autocrypt
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aJ6gqDclJps+92yMi2EqP2zs5MKmSwUtrEDcizFcW3Q=;
        b=Rw0vo3NbCYEOAolmKndM/KlamhkG7/qptfeifseNFlHSjPdaChZWRYelqyGxONLreK
         F9/Mn+gYBqMnrQ7M8OGuJUTFcf1aGj98wa8Z+7R+OXpcuutt2xgmF4W/fvb4onN2WGVP
         UX0v9yBki9pAc7wzIEOWWF0NJCKud3Z6+/J1zX7esuV3tQZSxDbwhINO4hoEe1gxdfH6
         wwe77s8MKrfXXisbGkEGrp/2EArfzukBmhV4RqvUfVBwWzdL6Eh+aANjYtyrI4pRR942
         OtuX85eN776iyG9A5zeu3muMod4roQrqvrMBlo+PnGisU8q34a3QfMM7PSZXn7LLS2aP
         FWkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:subject:to:cc:references
         :from:autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aJ6gqDclJps+92yMi2EqP2zs5MKmSwUtrEDcizFcW3Q=;
        b=nHyyfolB2P7jbtL/E++y8//8cquOoJxHqFSOp/3Re6BmdbqrxWoG6H5VXQvkfOgm2p
         eUHExZJFPnhavm9WeZYeg/P5SXiqBxw8baWVzwLqDXV30Sykh40aC0QhOAshm2szS8K5
         5ylWJLGfsDkRrN7aN2emrLa/813N7/bLUf4eJHo9/sOv2BhZtHs4hMcIN8RqVvD/uiFo
         a6JZykMaEd0wVVrF+anGuXaNFdEJcBIPlD4LIDVR7+tAp6jRzZfFg8fx+IxspyGOPmo4
         hRGUCWCY2fi/KwfhEoMIHqsvSoxEiAF9/cKymiKJmSVnxrcYJdQHv2IIkEK7gvpCKEZN
         pL5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVm3xEyc0qHbr+r7DWC5Z4OZnnJ5YFz4OiWgoEC8gf0nig1V7tS
	2K4bH463BM1a7JiQ5iPHLWg=
X-Google-Smtp-Source: APXvYqyEB0PqYRNfbhOyyKpJyfAtbIQie1rtX4mr+AXbXMiGv0XaAOz9nUfAnc8AytuLDx2xNyYo7w==
X-Received: by 2002:adf:a109:: with SMTP id o9mr10792122wro.189.1579691644554;
        Wed, 22 Jan 2020 03:14:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:e913:: with SMTP id q19ls2815540wmc.3.canary-gmail; Wed,
 22 Jan 2020 03:14:04 -0800 (PST)
X-Received: by 2002:a05:600c:54c:: with SMTP id k12mr2420813wmc.124.1579691644136;
        Wed, 22 Jan 2020 03:14:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579691644; cv=none;
        d=google.com; s=arc-20160816;
        b=itsNMMJPm0hR7rDlSu9er4041dkv5ITRg3CAFIEI9M8XSwe9EB8Q8zwInwRpJ92G5w
         VQ91iILetfnfQGW9CZ8dlpK3zMAyIvQe2+h+7eT6xER3YFqp59EpqZ2VJpkiwYSgWRkY
         Kj0J8ux0ete5MQHHfJajL45SfCWk3eqUIOucOpZOyUFcCxa7nC8bszb8Zqtg3krnxOOL
         RkEYUfhiY3zPaYZpeQlIibvNwf2h8ANWonzgeTUwlZq+CWPRUmfeSj1//O4M49bQO40p
         9SRINgPr+cipnNGia0TvZW2N/t3Vu4Bh82FOxvQNzTzATEhS48WeSseJBsC3FyMt2z3M
         Hisg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :ironport-sdr:dkim-signature;
        bh=MeQM2UxxDeac6E4ue3L0UrkqNV+ursdme1MC2ONHwhQ=;
        b=xAb0+AG6dl1tvOkYljezRWR8St9o2aCO9jT655pCHfQ9/Ldu1cXgx5mSP9Bgf29B5a
         J9ozPQD9+cDqTj+c8+sqv90ivtxMnsang6MPDM6i6pYMfnFU4PE2osr+n/VkouSKaNlA
         CgYDBZrLzoGWFLaGltKPBaUqM1oJljJuBzkmdUm/wWYFH6mAiT7GFp9W9d3//6qf7HMg
         8Wn9kWrRc/2C1dVG/V6467vmzK5OwMPPUq7H9WwX9yzBgt5aNX7FHWX2OlfHG6hJmSQ/
         IrmHdsEh2tgTNSSTtn+JS+0y+F3wzwHQiQc4gKA5SkR15yOfmyyEhR48AG5vMx/hPgvy
         SQ1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=VekwyUgO;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.144 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa4.hc3370-68.iphmx.com (esa4.hc3370-68.iphmx.com. [216.71.155.144])
        by gmr-mx.google.com with ESMTPS id t83si123759wmb.4.2020.01.22.03.14.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 Jan 2020 03:14:04 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.144 as permitted sender) client-ip=216.71.155.144;
Received-SPF: None (esa4.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa4.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa4.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa4.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa4.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa4.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: CDfu/Z3EtczMTzpEfAZPSlKPw+H9ASx9SLknEvZtvXAO/orpurrTD7fm1oG1CbkTm3bPIKKqcE
 XaF9PXjKhkCPzXqCgi84uDCo+RemjNh/65gMfG8+ZZ32QMpk2RC0NKgTJq8q6iPECwlikBFfqV
 bNWSAvt0+CdPwyWK08v4vI4mmHD7OF7uJv1TROtgDcKH63Mx1udzWkdfW54vrsqOxfLeSxbvn+
 XUN/aD7Wd1oz8Blud63w7wAdtUBgarO5W3lgetyx+NK9hMzWiaFaFhoa303hiqKFVJdBXapkfq
 10Q=
X-SBRS: 2.7
X-MesageID: 11856945
X-Ironport-Server: esa4.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.70,349,1574139600"; 
   d="scan'208";a="11856945"
Subject: Re: [PATCH v2 2/4] x86/xen: add basic KASAN support for PV kernel
To: Boris Ostrovsky <boris.ostrovsky@oracle.com>, <xen-devel@lists.xen.org>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Juergen Gross
	<jgross@suse.com>, Stefano Stabellini <sstabellini@kernel.org>, George Dunlap
	<george.dunlap@citrix.com>, Ross Lagerwall <ross.lagerwall@citrix.com>,
	Andrew Morton <akpm@linux-foundation.org>, "sergey.dyasli@citrix.com >>
 Sergey Dyasli" <sergey.dyasli@citrix.com>
References: <20200117125834.14552-1-sergey.dyasli@citrix.com>
 <20200117125834.14552-3-sergey.dyasli@citrix.com>
 <28aba070-fa53-5677-c2d2-97d06514dda8@oracle.com>
From: Sergey Dyasli <sergey.dyasli@citrix.com>
Autocrypt: addr=sergey.dyasli@citrix.com; keydata=
 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
Message-ID: <3570a312-04e9-c7f8-e348-e1c2dbd040db@citrix.com>
Date: Wed, 22 Jan 2020 11:13:54 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <28aba070-fa53-5677-c2d2-97d06514dda8@oracle.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=VekwyUgO;       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.144 as
 permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=citrix.com
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

On 17/01/2020 14:56, Boris Ostrovsky wrote:
>
>
> On 1/17/20 7:58 AM, Sergey Dyasli wrote:
>> --- a/arch/x86/mm/kasan_init_64.c
>> +++ b/arch/x86/mm/kasan_init_64.c
>> @@ -13,6 +13,9 @@
>>   #include <linux/sched/task.h>
>>   #include <linux/vmalloc.h>
>>   +#include <xen/xen.h>
>> +#include <xen/xen-ops.h>
>> +
>>   #include <asm/e820/types.h>
>>   #include <asm/pgalloc.h>
>>   #include <asm/tlbflush.h>
>> @@ -332,6 +335,11 @@ void __init kasan_early_init(void)
>>       for (i = 0; pgtable_l5_enabled() && i < PTRS_PER_P4D; i++)
>>           kasan_early_shadow_p4d[i] = __p4d(p4d_val);
>>   +    if (xen_pv_domain()) {
>> +        pgd_t *pv_top_pgt = xen_pv_kasan_early_init();
>> +        kasan_map_early_shadow(pv_top_pgt);
>> +    }
>> +
>
>
> I'd suggest replacing this with xen_kasan_early_init() and doing everything, including PV check, there. This way non-Xen code won't need to be aware of Xen-specific details such as guest types.

This would require exporting kasan_map_early_shadow() via kasan.h.
I'm fine with either approach.

>>       kasan_map_early_shadow(early_top_pgt);
>>       kasan_map_early_shadow(init_top_pgt);
>>   }
>> @@ -369,6 +377,8 @@ void __init kasan_init(void)
>>                   __pgd(__pa(tmp_p4d_table) | _KERNPG_TABLE));
>>       }
>>   +    xen_pv_kasan_pin_pgd(early_top_pgt);
>> +
>
> And drop "_pv" here (and below) for the same reason.

This is a reasonable suggestion.

>>       load_cr3(early_top_pgt);
>>       __flush_tlb_all();
>>   @@ -433,6 +443,8 @@ void __init kasan_init(void)
>>       load_cr3(init_top_pgt);
>>       __flush_tlb_all();
>>   +    xen_pv_kasan_unpin_pgd(early_top_pgt);
>> +
>>

--
Thanks,
Sergey

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3570a312-04e9-c7f8-e348-e1c2dbd040db%40citrix.com.
