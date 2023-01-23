Return-Path: <kasan-dev+bncBC32535MUICBBAWJXGPAMGQE777PGMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C5D867795D
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 11:42:12 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id c9-20020a9d6849000000b006869603817fsf4554809oto.5
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Jan 2023 02:42:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674470531; cv=pass;
        d=google.com; s=arc-20160816;
        b=QOQZ2W+8vozWB3Drt20dcGQi8xNgM9pmGs5fWug8ZqpHYii8XDMXelCsZTpnvDGbHr
         hLgyjlDG+vIHgMLty1Ez0TReo8pxnyyGNQI3liUpXQwruvxOyo1lyZrHbdN8Fvq9NDWA
         qUCBk6Jud6mXqPsGoaB9gIDnYcwyWoW+lfpk8L6xmoIo2T92He7mKOuNPZNmUGOsBWJ/
         yvD1Lfme4dmlIUASdxBsLUdHHyvDOZX71f9czWkYmMtdbIh5HoDTy/jM7PZshDer7a9c
         lo5JbbIbyN8ZoP0TYggKzxCPo8vuakvXdkaDcU5PjPVDfYl+6YArQTPVb7Og95zdcC8z
         wPOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=GGKr945fPXreNWvfaJKd5GtTGczpD0lovyNM71abQlI=;
        b=WRbWn1LS4qYEruJMRhoTFP7O8wIvZYzjLWKqSII4AC5CDHzoPhWpHepH5QUfwTN8gD
         69Gg9jLXqpMJmmOvh1rhGBJ9fd7XC8tC+VcdqyyjPKC8Sts2goaSv5Xpbg9gfRdNoV2R
         VB1D9EqnLQjZW63g8ztvR3jOLVjjH8YfMk2g5ahwOZao/FrG4F5/TbssA5TnNIhV72nM
         EgR6RBk4kzTL2llFDycKtB4YMInxjgPCQqkSeSv4kk+AvXBmsZjgJzsvykBePb3l/OF9
         P7EYdNj86wTwlArB4bE84j9E9lnM9BFFaBDFeLvhAStN/ejIpSlmd6gt4Mwg+V3X7jCu
         HcSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MkQtcEaj;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=GGKr945fPXreNWvfaJKd5GtTGczpD0lovyNM71abQlI=;
        b=sBVeUibizE3KpYqyVZMOofviSrSv+XcCvPsCDV8NevB5QyknGfvc58k8mRWENeTvCq
         c2inWkeNVQZHkiPLIroRWKWvC2Xpb81vFTmkffA5v0VYHECy9rz7+8NkAdqKWpQKx5tX
         zdwF39jzYnJUSWKrJl9BjLbzmCDmqAjG7qBeUEYF0CCjYwKRqtP/2q1PiLdRq3oGlJP6
         liOHGYa/O4fg+5hBPHv4Y2qc/gtI2BbZFSbxnCdrhIvmU793cKlJWpEgtTNNWMlrYR8o
         rWKDGNG2kc1GPxV0TcZ2r1VNWhSCbyqjsmNjJk+yj6Kc7+6cciXJ7QPClU3xu/j+CchV
         I/8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=GGKr945fPXreNWvfaJKd5GtTGczpD0lovyNM71abQlI=;
        b=x1B3I7B19VBApnQgemH9PQnAvFcffmzacJ2SrktPC8dVwvHI53dPAYADvXzztm7u0e
         4PQ9EqN9u2fNcxNPWONe7s4FOCc8WOnyi0vj42klRVkTKE+3tzxFEzSb43APdkKlkc/K
         ovKcfpUARdjq0PPsxEXjviej+gdvAJd6AQul2mDkf+DTfOV9Ryjo5pxAjNMSP5ygaPyy
         RGn3PrEfY//QyjyCwM7h0e2t1vtFyPSB3nFMRinYX8ZZVUD7boFQdvKzl6FS9/urskVG
         qeKYSwuW/jp4yEsU7rFAZRM6REPntBzgSDQayJow71ZJ9argpyYMJM1RQOI6/0Ivrai6
         MFTQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpDkrl4KpsGv6RPy57qMpUitgSw83V9L90+b8C8poO9EsPXJAkO
	+9r0VoEnw8BLS2QaB322p8s=
X-Google-Smtp-Source: AMrXdXswD4XIU+VuQNZYFznxw3bwrCIXvB0FOXHu/em2/8AtLbXTPZBHBkv/zYPFwXOw1Me/0BiZxA==
X-Received: by 2002:a05:6830:1db7:b0:686:3b42:b7d with SMTP id z23-20020a0568301db700b006863b420b7dmr1217726oti.36.1674470530967;
        Mon, 23 Jan 2023 02:42:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:b82:b0:686:6205:ecee with SMTP id
 a2-20020a0568300b8200b006866205eceels2250859otv.7.-pod-prod-gmail; Mon, 23
 Jan 2023 02:42:10 -0800 (PST)
X-Received: by 2002:a9d:6ace:0:b0:684:d5bd:56df with SMTP id m14-20020a9d6ace000000b00684d5bd56dfmr13483095otq.34.1674470530476;
        Mon, 23 Jan 2023 02:42:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674470530; cv=none;
        d=google.com; s=arc-20160816;
        b=ut00ALYQgswZZYXCsCUkyp2wq9blBL78F8A7QN6+uzQeC04bz+WFEmO1wY2rfDRlIG
         0n5tLa5RXzl8aEIeJcdcQ1W3Kud49fkvs6Rm8sIGc5nqyak9hPduwsoAF+dQh6NQB56w
         O79LTEBhD+i1BWmw2pDR5+yc8HF1BJ8KUwoUCK+UVWZh2UWsKKUBc9L7O+KMXTaMOP9K
         bgsQ9wmQHJmoQ92/ukWBwFuApc1UPBqvjy1WbhG/kZ1uTQHS7az11Pqy3OAmmeizdHvC
         NIv8Dtknb3qO7LemYxOgvytDzb4Dp7zqBkXjI2wBwHCBnUS7C2Zw1Q40SSHd2d3LQPjw
         e6Ew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=sFKdgVkIDHWZa+NsXoTbB7afVZnwuNP7L4nWLFtij9U=;
        b=M61MpTXj4/ot7LS/OjAqQm4dr1okK37E19C31y4pIaoSoDlWNbWpIaVLOR4zL3kqA3
         qNKEUr0PFgHi0Ekhpo4PTw0RTMBonc3YAetJ5L5ge8hDAxDp2q4lrJp4tqqKSLMwfYtr
         S+WOpU20WOgsLOLRChA72rlRVE44/F2QsmeLhVKIHVH2nU8tig484BTu7t/tCC4FERcB
         6KPneME/KgMdIaDv6KQeO05Gwo1W4wic6Vmv55QKqTht06H9JGVJ/DzJgyXZR4UnU9/v
         ZLhPnCVv7nEfuQWiL3iitB9AdeH+PA/GydaCXyMmrA/Nn/7D3TDrjCRFOGR8XtawpMfl
         9Quw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=MkQtcEaj;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 46-20020a9d04b1000000b0066e950b0580si4332452otm.4.2023.01.23.02.42.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:42:10 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com
 [209.85.128.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_128_GCM_SHA256) id
 us-mta-529-TgkI1hqBNPu1UfyLbpkWow-1; Mon, 23 Jan 2023 05:42:06 -0500
X-MC-Unique: TgkI1hqBNPu1UfyLbpkWow-1
Received: by mail-wm1-f70.google.com with SMTP id ay38-20020a05600c1e2600b003da7c41fafcso9223590wmb.7
        for <kasan-dev@googlegroups.com>; Mon, 23 Jan 2023 02:42:06 -0800 (PST)
X-Received: by 2002:a05:600c:684:b0:3cf:5d41:b748 with SMTP id a4-20020a05600c068400b003cf5d41b748mr31509099wmn.36.1674470525388;
        Mon, 23 Jan 2023 02:42:05 -0800 (PST)
X-Received: by 2002:a05:600c:684:b0:3cf:5d41:b748 with SMTP id a4-20020a05600c068400b003cf5d41b748mr31509074wmn.36.1674470525126;
        Mon, 23 Jan 2023 02:42:05 -0800 (PST)
Received: from ?IPV6:2003:cb:c704:1100:65a0:c03a:142a:f914? (p200300cbc704110065a0c03a142af914.dip0.t-ipconnect.de. [2003:cb:c704:1100:65a0:c03a:142a:f914])
        by smtp.gmail.com with ESMTPSA id i22-20020a05600c355600b003a84375d0d1sm10978391wmq.44.2023.01.23.02.42.04
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Jan 2023 02:42:04 -0800 (PST)
Message-ID: <fe7617a0-14d7-4ded-8d7d-639183219169@redhat.com>
Date: Mon, 23 Jan 2023 11:42:03 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.6.0
Subject: Re: [PATCH 07/10] mm: use remove_vm_area in __vunmap
To: Christoph Hellwig <hch@lst.de>, Andrew Morton
 <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org
References: <20230121071051.1143058-1-hch@lst.de>
 <20230121071051.1143058-8-hch@lst.de>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <20230121071051.1143058-8-hch@lst.de>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=MkQtcEaj;
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
> Use the common helper to find and remove a vmap_area instead of open
> coding it.
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fe7617a0-14d7-4ded-8d7d-639183219169%40redhat.com.
