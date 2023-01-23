Return-Path: <kasan-dev+bncBC32535MUICBBOWFXGPAMGQELBSOOAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id EFF0A677941
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 11:34:35 +0100 (CET)
Received: by mail-ua1-x93b.google.com with SMTP id k12-20020a9f30cc000000b0059bd6246237sf3200434uab.7
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 02:34:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674470074; cv=pass;
        d=google.com; s=arc-20160816;
        b=rE5HO3b4n1DmDcYieHZohoTsac9pO+jILUzkK07NHLAEHTLq7qQ3GntjJsPI7Zkda8
         4EORnRSFjzTcw+wku9O4IUn63JK1YlM5vKdcV/r6XflKZwsPgE+OLmGusGVheJvhBFVt
         fXRn/bhY/qwCHWICid79YGd02dE+VTdcx52zbDlMOE88/bg8lz21OdMDSs/bbAFbOMSL
         9o5IEJgqejgV00tflaUOfTc+JMhkvi9JHnpIpo99gqY8XxquDpzmpUU5ushQcDxRA1vx
         1q7U7CAdhQulIYAMAbSRnCG2DalkNAg3JepdNq9BLIZoRtxiM0XfUBIcPaCqLhvkC9Cz
         I7gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=tPV8l9xA5Sd9pOOP6fl/5iVit5JmzDQA9rB7DLg3UuI=;
        b=cXUUSOFbmqbfGeC9/YQcgC3R0MUQyhALR8jTJVU87LxNrSLgLKKndi63WFn7hbxZzO
         ZP7lHWUdQTNVWsI+wLDflpM9SNlsZkCtKYZvV/Ah34oz63n8/8ttRLIoLCATwGM5s2BI
         Trkm8a1jLD4SWUpT+TdCX/W+0bPW9xHBQ8t1KyD6aSg8l5LdA+/CBcQ6MpcZ65u026O6
         oJWABP2Qn0VSufu1ewweBH9xPTe5izdxCs+GP2GsP12ssPriCDSlV7So/4FdQF7gi1+5
         jZS0Jk4ee/q7XO74+KF2li7oY0DunNr/5YWLtZLd6+C77G6zqy9XexdRqrVoyEUaxeOI
         HTkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=H52XZ+5r;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tPV8l9xA5Sd9pOOP6fl/5iVit5JmzDQA9rB7DLg3UuI=;
        b=mCyr/vbCHM+b9Bdb52l38/PjXjT1CLQO8h1jcacq7UgDAhm/9uE5i0aW3IE+Wf7cYc
         1ZXtp3KxTrTfJTqo4dhGi6GJ+70oKSCFQOeGCJ/TEv2ZiBHujcRf6rpq0lwCjv8Arv81
         cMIEmVqU3+VLiTg/lsnBt9bHKqSqZg5Qp0i/tBsHrvgG4b3hngWP7KZVjoITv5A3iMTa
         g5YP2GJyDiQ68eP+yuolA5BulUMkz4vYX9eMPlsbr1s59HorAbSfmO3COxrPoMSycbHE
         DkKZqN+XYDhIQgWzun4gkHo9TQMOMC4McnrNhObdwhgcWi0sY/4Qxc5Ki9OzX/apvfYZ
         6ESA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tPV8l9xA5Sd9pOOP6fl/5iVit5JmzDQA9rB7DLg3UuI=;
        b=7Y85gleZPqldVt5Cv6ySOCA4kcPhQVoZOrJqyQ00daeSFI20WEHZ1Jd/+vhB1UV25f
         wnUDZBDTbWCL1tnUGWG0muYRSYH7flTmgxpqZbCvBVyHM1SRfy8Bm8xeJZPQsg3gm5KK
         HqsP/HKU8hY19V/1a6g0I/Sq95PVZORUAON4bbjvKekHVzqJd+Pfo3SyQ6O50XB0fH0Q
         tfrZdIHom0tc5foWWJDS6sjjmnWE+ofpJ5YFuKj/slnt89qbA0CPVQDnUktQnRGavby5
         Gx2TcHZ96V/VSdnc6M/OrgI7wc4aFUVu6/QIRoreqQLvZdT/bKvCypnRTs/G9KFAddqB
         zoYA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koFGB3x/l+X/SWghJs9vdZ641a7rq3Bmis2/Ikpb81voCFFpfy7
	8iVneWPaaUbsErB+QtwrTvs=
X-Google-Smtp-Source: AMrXdXtQYb6vZDND/CYK5Yx4zo54dx+TfR/uB406F9O4ZB5ZHaN67OnvSsZpcoP1U5gArQtKUynYAQ==
X-Received: by 2002:a05:6102:5490:b0:3b5:1fe4:f1c2 with SMTP id bk16-20020a056102549000b003b51fe4f1c2mr3192455vsb.0.1674470074571;
        Mon, 23 Jan 2023 02:34:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d20f:0:b0:3d2:3980:e728 with SMTP id y15-20020a67d20f000000b003d23980e728ls3858718vsi.8.-pod-prod-gmail;
 Mon, 23 Jan 2023 02:34:33 -0800 (PST)
X-Received: by 2002:a05:6102:2135:b0:3c8:f1de:f5b6 with SMTP id f21-20020a056102213500b003c8f1def5b6mr12798563vsg.8.1674470073869;
        Mon, 23 Jan 2023 02:34:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674470073; cv=none;
        d=google.com; s=arc-20160816;
        b=Pho1+w4vnR9Faf2v93Z74j1xA1zgQ4pjyNXElb+TJrV7kKf/XWFxRx9TgLw95ozTas
         ZX+9yF0OMSOO5sgEPrw5JO+qLKVEAq2Uj+hV4k5k4C/XS2qm1+ZdECd18F12P96hYdlL
         CoJrsURk16lHQLIGwQPV1YYd4yFjWe/f7mb6YpjHTDASADFv+ZLxoGFnmwCNNXd/EIwy
         RrkxWwdh2/VNJN0GZ+ar5UoEinFetNbYViJ2iZHW57Z33Tyq87aFfxXGhMothq1uHAZI
         /3Bnvsqq4Oj7ijUZkA7xADMVdpykSLSfayBCXTQO+NabxajJhF4SK3GZdT1adRnuXNTd
         t29Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=CGkTtXjMJ0EjzS8ngVp9e2oUkRRYJC5lbvd8du7yqlI=;
        b=VaaSNKnd26J2bm/blRWfHrXI4/cnMaBYMcYolhw4GD9EAPvCa+Q4Cr4+hsztjIiqwi
         duf//Q5g//4htInK9A3mYICJ9QEKxFwaTjRefWoh8r86btVaeSvvIPIbsCM24555upCG
         c0L+NNXs3Kr8xx4M2/+ahWc5P/upXQjSFAzq70yvlA/modA4AROyL3IJ0TbkZcv+lPvG
         grNGI6Y3Pm4gkRG+Kw1jKALNfl9MTBjmQNgnanwLFh6Vb+4a4P5Z9it5qN8JRDzgrFRB
         ETG3CfFuTT9aH1wz3Xfy7x6tCk1NCjPUQRxo/wDcvB3PKwFEh3nYxjAuOVFxvf4Uabfo
         HVfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=H52XZ+5r;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id b15-20020a67e98f000000b003980b6c8861si3444666vso.2.2023.01.23.02.34.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:34:33 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-526-Xsp8K535N22CZpDIngG7jQ-1; Mon, 23 Jan 2023 05:34:24 -0500
X-MC-Unique: Xsp8K535N22CZpDIngG7jQ-1
Received: by mail-wm1-f72.google.com with SMTP id ay38-20020a05600c1e2600b003da7c41fafcso9214698wmb.7
        for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 02:34:24 -0800 (PST)
X-Received: by 2002:a05:600c:4e03:b0:3db:262a:8ef with SMTP id b3-20020a05600c4e0300b003db262a08efmr14478499wmq.38.1674470063467;
        Mon, 23 Jan 2023 02:34:23 -0800 (PST)
X-Received: by 2002:a05:600c:4e03:b0:3db:262a:8ef with SMTP id b3-20020a05600c4e0300b003db262a08efmr14478481wmq.38.1674470063197;
        Mon, 23 Jan 2023 02:34:23 -0800 (PST)
Received: from ?IPV6:2003:cb:c704:1100:65a0:c03a:142a:f914? (p200300cbc704110065a0c03a142af914.dip0.t-ipconnect.de. [2003:cb:c704:1100:65a0:c03a:142a:f914])
        by smtp.gmail.com with ESMTPSA id fm17-20020a05600c0c1100b003db06224953sm12144105wmb.41.2023.01.23.02.34.22
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:34:22 -0800 (PST)
Message-ID: <1657418b-56f0-54f2-8aa8-6740a52fad68@redhat.com>
Date: Mon, 23 Jan 2023 11:34:21 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.0
Subject: Re: [PATCH 01/10] mm: reject vmap with VM_FLUSH_RESET_PERMS
To: Christoph Hellwig <hch@lst.de>, Andrew Morton
 <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org
References: <20230121071051.1143058-1-hch@lst.de>
 <20230121071051.1143058-2-hch@lst.de>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <20230121071051.1143058-2-hch@lst.de>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=H52XZ+5r;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

On 21.01.23 08:10, Christoph Hellwig wrote:
> VM_FLUSH_RESET_PERMS is just for use with vmalloc as it is tied to freeing
> the underlying pages.
> 
> Signed-off-by: Christoph Hellwig <hch@lst.de>
> Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
> ---

Reviewed-by: David Hildenbrand <david@redhat.com>

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1657418b-56f0-54f2-8aa8-6740a52fad68%40redhat.com.
