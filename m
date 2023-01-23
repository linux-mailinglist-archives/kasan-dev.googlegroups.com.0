Return-Path: <kasan-dev+bncBC32535MUICBBCGIXGPAMGQEPUKOZFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 17700677959
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 11:40:10 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id de37-20020a05620a372500b00707391077b4sf8596503qkb.17
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 02:40:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674470409; cv=pass;
        d=google.com; s=arc-20160816;
        b=t2LLFjVn5vzGHxedtIHs8dy75KIKoYweTpVI/wwxyaFZ47KMuI3sXxWK0Pq6tvk9p8
         KqddCChQcH+hG/9ok31H+x2c6/kCmL/pvhBzrYzro4SOC1P7+16vgUoOnUMkjLcnxE4Z
         5KWYL+ciOZ3ZPyNKq2GUWH3Iek7hpDGA9mgPQDVBhAMMdCp4TRR67gJD1xs4uRP6RQM2
         ghAfRzf+FwrM8MRTa++HExc+S369GIEa065iDCKRPxz3QV2BIpn67+wp7krUWyTdDb+V
         tJnh1MxohlovFlWQc+hA+cDyTVRaxKbvY2H+Vq7UxIItDgi3Ww5dY50B/Ag1zIas/41Y
         pvEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=RblqYmMot3m22q/7c/t0b09f77rwzErRpmj83e8l30s=;
        b=itnPHos9kg6ZRNqwJsZMGpQM2Zl6ipvLPX2q8HV4yV75onXk4+FtxVv/PaPSs9r1/A
         KIznU55B68QCs760c2Fktl0VHXmWnqCbw4CMB6VW0aO+FC5LaZZUX1qCGlMRw64WItnF
         d6DthdExltxUgP92Fv+ThCGscyl9uMk2E9880qDpCH1BQCTFIYF0aBAN7PHzjFDHnh6n
         hNZsbM8RaZ7X/mmcu8TKvpKV61PvLghgzpXhi50lh40G9vriXWEG+/rE4VClJjeNxFYO
         moEmLpKkY3eduXMDoy1xcULN109e222lTV5E2waIHf0KD762kltCWK2QO34DK7XQdfr+
         Nn/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fKUEW5jv;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=RblqYmMot3m22q/7c/t0b09f77rwzErRpmj83e8l30s=;
        b=hqEl4nuOPnXZ0h5jolMFAcUs5x/ERRju92CiiRXC+85eSRVvGBc9L5kAE2pZRvhH09
         09r78HpuWdBbpxICyThB56fs8V5i+04mIG+1nreVVxfMWoJxrIcbXw2PTrPgFEdxE7RJ
         8SnzLg/Jzmh3m+Ip5tYBKsC0ajKc1vITntbOtv8KhF28XY0YWHcHGjQhmH187vDrofqy
         oDsQoIqIyyPpmV89q9xzizpiOoKpkySV9IwehU/T28z5TUP89fxm2TWXU2d+hxGkVQS9
         6v0s1ybBf7X61//8kpjFp4KalAKgPc0RHkGNrcSLdxfWoshE/GviBbzFiCIVdlO0OZ/0
         fBKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=RblqYmMot3m22q/7c/t0b09f77rwzErRpmj83e8l30s=;
        b=UMIqNHNBt3gg9NDKMPNjOsqLHdpy0wI1C2JaVUf5m6mL7bAD9NhLpr3op9UYjL1PAL
         jrOnWquwmC5gmYCXv62OFRWgLPcxTjSL/Co5xYiG5vCrlLRZpAWA97y0a9Ui+Lu+jslQ
         XzI/o2AVh01rHNcu7TJzxqbHmfl3MM+TXdM7Bw/0dECxpUVZxKWYfhAVeCZirlfqsV2H
         1UdSTgGRckbj9DTZW62GpTiRBjQ+EHanOUUj7dSA+imfKzILGxJTMSozZeWZxmeBLGds
         PsAVoJgmLmNTY2Bo+17Poxs06DRR4r5bUqc/1ZhzBonb5KuO8GVj2006qmWgOETjrjuk
         4KrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpoCrs4ExhRJUt38i4oVX0BG/Xf9gXEv72XRCyivz5Lnw/F2YEn
	19OJdPsuZ2Aip3bXhou9nOM=
X-Google-Smtp-Source: AMrXdXupd1NYYrtO7UyxCfMqC0ifAmjDIfTQ5P808cOSi/WYVW2jTDl7Wb+7ltkOlxk3ceYK9D31Vw==
X-Received: by 2002:a05:6214:3983:b0:535:1a2a:6ffd with SMTP id ny3-20020a056214398300b005351a2a6ffdmr1289005qvb.18.1674470408943;
        Mon, 23 Jan 2023 02:40:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:b3cd:0:b0:531:d0e0:dbaa with SMTP id b13-20020a0cb3cd000000b00531d0e0dbaals7296183qvf.7.-pod-prod-gmail;
 Mon, 23 Jan 2023 02:40:08 -0800 (PST)
X-Received: by 2002:a05:6214:3492:b0:534:2b55:6320 with SMTP id mr18-20020a056214349200b005342b556320mr36062351qvb.9.1674470408413;
        Mon, 23 Jan 2023 02:40:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674470408; cv=none;
        d=google.com; s=arc-20160816;
        b=gL9mD6nu4SNu1vFuMqOWVjqZOxOhdnB7Lw70NMt52IM+5JkbQQB+fNXaKrx9Dx62bq
         rXnzKkja6ouBn/AZnQW5bXLFu5xNSa3xi6ti4h7GCjGlg0s0JCM/KOX00bBSki25IGSk
         XciKFTa/r71JZEs9i9MGsibCEF1Ay+roq8o2Y820Gp5g4N+VTfjgJYQFrn9ZXXk7qjYE
         sKyQoFWNqq6XU9WVrkwad5JJOBROD8mf1Gl1BMdYkBsuPubwuEFivyRmjxDcYhxNNFXo
         /vDWeKsL4qSeLf0LF0unuaS3m8jZprpyl2SjNEAgchk72NIZ5fHNpmnNq054c7nb8e8Z
         pTSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=ZJuB1i92/qdAPwFfZ/HHyZ1sJ6prxzJjK5/SeluURIQ=;
        b=xc0xi3eBh6yXkRfR4HnSFM1RCj+zm3Nsj7gvFPa6JrPWhpsnqKnO3d0IRI5D+1uTKZ
         LSsPRfrEQDTqajhqMiUhZQhnWquVo3B2hVR6yYJrzU56CJvZrBCVY94sJaarhD5QqEdD
         1BY12R2YJIkCypQfrjI2mrTKo1orwzMIj1Ra57krGerxP9VFUM26SkjN2LIQfL5ztmBP
         NAYYhd9Sf5sJxcmbou5A3u2cLiyGCJxLl+IFBaOkQleFJJl51d9Y6WY2yKxhfA/84XFt
         e6cL3GogNiCNJCZT5nnsopyzKc/rZbjVD+p3RIx9Cmxv8Gq2vfQK2jN9p1C051dFbj5I
         S2Jg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fKUEW5jv;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id i10-20020a37c20a000000b0070917dc5829si745234qkm.3.2023.01.23.02.40.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:40:08 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com
 [209.85.128.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-301-ruBBS84kPeqhsK4cvli8kQ-1; Mon, 23 Jan 2023 05:40:06 -0500
X-MC-Unique: ruBBS84kPeqhsK4cvli8kQ-1
Received: by mail-wm1-f69.google.com with SMTP id o22-20020a05600c511600b003db02b921f1so9210505wms.8
        for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 02:40:06 -0800 (PST)
X-Received: by 2002:a5d:6910:0:b0:242:63e5:2451 with SMTP id t16-20020a5d6910000000b0024263e52451mr25102734wru.71.1674470405617;
        Mon, 23 Jan 2023 02:40:05 -0800 (PST)
X-Received: by 2002:a5d:6910:0:b0:242:63e5:2451 with SMTP id t16-20020a5d6910000000b0024263e52451mr25102719wru.71.1674470405286;
        Mon, 23 Jan 2023 02:40:05 -0800 (PST)
Received: from ?IPV6:2003:cb:c704:1100:65a0:c03a:142a:f914? (p200300cbc704110065a0c03a142af914.dip0.t-ipconnect.de. [2003:cb:c704:1100:65a0:c03a:142a:f914])
        by smtp.gmail.com with ESMTPSA id k2-20020a5d6e82000000b002be5becdb89sm7499010wrz.3.2023.01.23.02.40.04
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:40:04 -0800 (PST)
Message-ID: <54ee465b-549a-6c49-184e-f529219ac33b@redhat.com>
Date: Mon, 23 Jan 2023 11:40:04 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.0
Subject: Re: [PATCH 06/10] mm: move __remove_vm_area out of va_remove_mappings
To: Christoph Hellwig <hch@lst.de>, Andrew Morton
 <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org
References: <20230121071051.1143058-1-hch@lst.de>
 <20230121071051.1143058-7-hch@lst.de>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <20230121071051.1143058-7-hch@lst.de>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=fKUEW5jv;
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

On 21.01.23 08:10, Christoph Hellwig wrote:
> __remove_vm_area is the only part of va_remove_mappings that requires
> a vmap_area.  Move the call out to the caller and only pass the vm_struct
> to va_remove_mappings.
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/54ee465b-549a-6c49-184e-f529219ac33b%40redhat.com.
