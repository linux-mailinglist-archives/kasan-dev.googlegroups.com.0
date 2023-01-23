Return-Path: <kasan-dev+bncBC32535MUICBBPOHXGPAMGQEZVZYJKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 48650677953
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 11:38:54 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id w2-20020a0565120b0200b004cfd8133992sf4836641lfu.11
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 02:38:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674470333; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZMLqjLqvo+yZewNvhuzDAj1rpDnMnAXovrgc2fkB1vfRAsai7bw6j80x1/+E0jASj6
         +LyRIjr3w7TTO6KAD1ffk3u4y7dvV8/yEqlK4JIaVZ6SDdZsBrTjbFeYVx1krDEMNng+
         wyTkjPECOMebacIxiyhxfyw3OBT5vIB8ct/8N3NrVIlSvOtvNlQLacCCn4eqZJb0+V7v
         X2EaRhOfPfAmp+h1Xq6SJC88tJ/CmdVqHIGrBf3gnpedEqODdj171psoerOI9ZLh8OPU
         0GTp/YmaYzzo/7TmbtC6QVcQJr14u+4H9rNMfgHYMsN5z2U2shQVl7DEYNCb3PhqccEX
         ZMlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=KnQxCvpjwQHSSyqIEYaquDkLXSwgOclCd3tO9p5qMmI=;
        b=DoSys5KGl09jaD/FRUdxrxiNJWcDoMDEOFRW3wGKcsZdU8HetVp68DUB20tBpATGRD
         wEeyifqCyuh0CRY+cB9TycdmurGwA67dIK2GCT+VFGpUG7p2omue41KgN7757L+EVETG
         MomI0GLCUtv6FiI2Ns3DhN0lw0YWkKhhF01wtO+BKnoRmTTFv6N4dSwxtki9RTuCpb4i
         l5YqIUZ6q+ec1tfFerOx6czrONSmFa6aAI0PPsF5le1GSFUDfnCx7UMU5QNdS+Lvx35g
         1P3kFGb0u9C1Rv1CbQuJrKowlbV9u/PkLE4Y2zH6Phlh3at5YPXPGRqHO2bw2/ohNRUf
         OG5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="A6Hp/jPM";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KnQxCvpjwQHSSyqIEYaquDkLXSwgOclCd3tO9p5qMmI=;
        b=JMW1QChYSFZJvGXhGK+ts0t1v8wGrT7Xhc3J47n6IH1t6DHLd5gv8QLuRTAClu5x1Q
         5RYqTInEHu0SmTDxGLD4i0+YXQ8Vb86jSOkuTjx7yFIe8utjviizvBhUwtVeY//75BFx
         bxk+RLzG6ko3gEv0+z6dqs83I893PqHfaXrVSo9Qz/KlgQ5/YQCX8Z2KnJXeuTXeYYzQ
         Sm5U5gCWSlK7nV6YEmgvldX7exsTiuejlcVSEf+Akvm76AAxeliO8ghdgCyjHgcjPB4t
         PxiF3qeaXi/yVQKhQ8eXUA7HoNSzYFtNxEIS4MlMbQ3VeKdu9B9D+O6nq4btTPSqCk9h
         k3Kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KnQxCvpjwQHSSyqIEYaquDkLXSwgOclCd3tO9p5qMmI=;
        b=bnoAzbVJpayOTEgfMMe28+AOMy0dgqpTWa6hAOGIEH9E5jW7EIvnk10NUrzkmRDO39
         Wp9o3sm4pxWDM0EpKe7W8rpWlyHjOIqlh0Z1LUYGFq35NGSlZwhCDt4YJO2qgQPbjJ83
         olYb9KKTEkHTig7Xa+9aKNoqVzmMwV/zuKj3edIRqrAtiu81hvJr73Lnk59CQUb3HwKe
         JCgT3grlxbNm8n3We0ACe2hGTuRTFpVaxEa8bpoOzRf9iWllVJliVovAtEfXzOuEqh9w
         vJ1c6eX0be+hr6dPSiXldmuBspkP+CbHTIJK/uQZGCaC9heR30ZsYNMjeB1erUdW1tRx
         1ePw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koW6K0Nq4cqeAvMtYVk1cFd0/ondfvMX4c95Yt+/MWFOG7l7oLk
	t+yCnzijNhxBLLHxJUf26uY=
X-Google-Smtp-Source: AMrXdXsjg3EcGBo1KIb1KbqM2aITfWP5uB+AMT6x6eo6CD0lhlOsCMjV1DP9Cd10CIbZQFAlMXP6kw==
X-Received: by 2002:a2e:a0c7:0:b0:288:791b:71ee with SMTP id f7-20020a2ea0c7000000b00288791b71eemr1730029ljm.521.1674470333472;
        Mon, 23 Jan 2023 02:38:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:368e:b0:4cf:ff9f:bbfd with SMTP id
 d14-20020a056512368e00b004cfff9fbbfdls4148481lfs.1.-pod-prod-gmail; Mon, 23
 Jan 2023 02:38:51 -0800 (PST)
X-Received: by 2002:ac2:59c3:0:b0:4cb:63a:54e2 with SMTP id x3-20020ac259c3000000b004cb063a54e2mr5662426lfn.41.1674470331887;
        Mon, 23 Jan 2023 02:38:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674470331; cv=none;
        d=google.com; s=arc-20160816;
        b=XT6zDqi1linQcI0uKEclhmirz0MTcOfuE7pvzn4VOoFBRsbyzQu1rDeH4febKsjMf3
         FFPBvfrwIu24UkykunqhZhwYmg7KLxGcKlM0cq4H4n2aZbzYAflh1m1gnDPfEn6ZEzEZ
         QBRQ68j6Q2VK36DovtCuYnZoSoyGukHfDar7T/sIqdCB9BUDUyBSRe3j/8UpKdxrBIbl
         /T3Z69xrNcUHClnqCMhM73CE9nhWpBGamygyz9aITu8dKGJUAfrkzwuSRuiGl4WSrzL4
         ttWJrb/X083gPiZlaeTxiOpKKSwjSvatF0MoQQCcv+Pls5toJosoNM1xo0iGK+yZtIUX
         FG3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=BVKRO3yK4TE4av4GZ4qrV6HLIzYER1ahPj7ZKLJJ2+M=;
        b=0QxkSls7xme14krdI/5XITPe7GdjxgVromoJHKkMscEG6PNQhImwODWr00dtNlkaV8
         gOus8N+4O673VjcAsdt7rsKlj3po1zUlkyw98cMBEvzEDAk/IuSoXC43Bum1p+xyqZS5
         8NdaomeAz1kVEMGzmh23myXM2cwqm965Ozpq5dN1fGOGyKgahNEotENcDQRkK6O0Outr
         Hz8QUFYZERxIurCVtmMubXrttrHmkzcv06jG+THzN2vJQb1PIjryi/Xv7xLtfTi+yAwv
         4yVwSKz2na5X16r1rbZVTfK3kCgeKvWXHixcqf7SxVKfu9nJVBTpL96HDY9Sa++aMLpx
         4hiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="A6Hp/jPM";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id k11-20020a2eb74b000000b0028b7cc84addsi1105148ljo.2.2023.01.23.02.38.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:38:51 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com
 [209.85.128.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-642-tKY1Xg70MQeDNxlPeHgbFQ-1; Mon, 23 Jan 2023 05:38:49 -0500
X-MC-Unique: tKY1Xg70MQeDNxlPeHgbFQ-1
Received: by mail-wm1-f69.google.com with SMTP id m10-20020a05600c3b0a00b003dafe7451deso7290881wms.4
        for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 02:38:49 -0800 (PST)
X-Received: by 2002:adf:f7c5:0:b0:2be:5a87:4e5 with SMTP id a5-20020adff7c5000000b002be5a8704e5mr9969885wrq.12.1674470328527;
        Mon, 23 Jan 2023 02:38:48 -0800 (PST)
X-Received: by 2002:adf:f7c5:0:b0:2be:5a87:4e5 with SMTP id a5-20020adff7c5000000b002be5a8704e5mr9969863wrq.12.1674470328206;
        Mon, 23 Jan 2023 02:38:48 -0800 (PST)
Received: from ?IPV6:2003:cb:c704:1100:65a0:c03a:142a:f914? (p200300cbc704110065a0c03a142af914.dip0.t-ipconnect.de. [2003:cb:c704:1100:65a0:c03a:142a:f914])
        by smtp.gmail.com with ESMTPSA id m16-20020adfe0d0000000b002be36beb2d9sm11234127wri.113.2023.01.23.02.38.47
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:38:47 -0800 (PST)
Message-ID: <96cd68be-674f-8def-b82c-a0e17256ed05@redhat.com>
Date: Mon, 23 Jan 2023 11:38:46 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.0
Subject: Re: [PATCH 05/10] mm: call vfree instead of __vunmap from
 delayed_vfree_work
To: Christoph Hellwig <hch@lst.de>, Andrew Morton
 <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org
References: <20230121071051.1143058-1-hch@lst.de>
 <20230121071051.1143058-6-hch@lst.de>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <20230121071051.1143058-6-hch@lst.de>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="A6Hp/jPM";
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
> This adds an extra, never taken,  in_interrupt() branch, but will allow
> to cut down the maze of vfree helpers.
> 
> Reviewed-by: Christoph Hellwig <hch@lst.de>

Self-review? :) I assume that was supposed to be a Signed-off-by ...

> Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
> ---

Reviewed-by: David Hildenbrand <david@redhat.com>

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/96cd68be-674f-8def-b82c-a0e17256ed05%40redhat.com.
