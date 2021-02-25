Return-Path: <kasan-dev+bncBC32535MUICBBMX23WAQMGQEEJDKWIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C63B324E3C
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 11:34:28 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id 97sf2750107otm.11
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 02:34:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614249267; cv=pass;
        d=google.com; s=arc-20160816;
        b=q1kSFydwmqIMF7gF9J4GgLjIEAu0RD7RMtuvmwjYrWs+cavLWjUVuFZpLycKC6oxrF
         Txjhz1p8AIiGecEsUfsUxHL+4wnal3TwCb2UR5IiHa4+GqAJm0ELtoU20k5E/b8tIQzP
         YIeGoKg1e/zdqCy2ab1WDs4okYz4458wDuDieqiMRp868sdy/7UeUU1NavO9O5iAQx6n
         S6QedGYntWFEz8VffdkKqtnN8OBNqhCigmEWNSn02J/jChB5v82wtJwJE8Rjs/LkQ4J+
         R9gJMvbDXwzgrjo/XLTcQWGGd0Ar6pnHCNMPQdiNz81wHPScA5qUnOocHGTNzw6qqoVH
         EccA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:organization:from
         :references:to:subject:sender:dkim-signature;
        bh=wMhpHYsyi+r8tX/GK5jxX7ZzmA2o5X82+ciy7jNkBI0=;
        b=lEzRo/vl2Hh1aqqB1HreeYX0YdQnqshAYkBNfYyoSxpr+wuZMV8FsJ+d9j+10keCO6
         +6jYBomXd3/fbd38mfN5HFHkJkDVh15DDs1KAYuRADiqNp5kvQt0RXN+JrVzvxkpWNUo
         oes/iuRdcHnIgB2vweyEw815P/zZckKq1LBiKXahBsjspXFxzkiMaPs221IzTtRYmpuB
         3M85KyYeZZOst2cZvVGF/ESrWaWYd0MjLukOZb5X+i9kosOuccsAxF6Q9QvwxF9Cu6AJ
         ecD4IIleRp2oPpZ37OR1Q67E4WWmkqNEkSoH9z6SH8mSbZYcO/LqOuTQ8k1F7Rnj/IWD
         taTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fpVtCn5Z;
       spf=pass (google.com: domain of david@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:organization:message-id:date
         :user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wMhpHYsyi+r8tX/GK5jxX7ZzmA2o5X82+ciy7jNkBI0=;
        b=RuWOh2zbsXxFtWn+Y9BnWWqCyECMXd4fkyJHc0Vz9GvrAtf1iWKsqJWcFaFdehEFRw
         6hVr8ryXLkb+TaZkdoN7EFl6ermVTvBZHZHiJjil/ewT75bF4mvSFhXU2nDGL4P1oN/L
         5K1w2fJYLK2rMtqAOC7T76n28FmrvVzgH8dbNhiQJEkCRuHSEcROoxQt4vCGvK7JH4vj
         62j7IzCgNRYO4/GBeWTQMD/WFpJvrU4tRPJUgbzXIYYrA/nnP0FOm1CdF2uRduW5GEGH
         50DIkB5pyLOQLmlS0sQ/itQL922tRmeGnYhWoYZ5GW8OqgPqaqofHtv7tIU5vafWe8+g
         sPBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:organization
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wMhpHYsyi+r8tX/GK5jxX7ZzmA2o5X82+ciy7jNkBI0=;
        b=MiAd9uzVw3BR2MOebx4uxcK64vdFaOYzMTDA7HyKcqUv+T/+YBNKsX9pgAO/YrxrOQ
         +uBDdLET00DR1C289LE8bGgvrD74I1jnxU+mQ9tsH2OmCQ4WWlQy9Z9aMJPzio5EiDhB
         5HVHezTnBsWGhSiRdMdDv1eFOK0QyL/gAQ1T+NaewdE+HXlyr9rAXZcbpc0t4Oiqyss1
         hDxNIF3htAlpkPDym+D+4GNSxJxHUiixKUQAly3wjZW91IQMdjskNxSbxVgaMIcpaKAI
         0LmDlVr/WBRJ7oWJXLynHkbHhBfFgw8AM/ZK2GRm73/HTLNR5L75FGi7t46CR3a4xnpr
         NNNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530NKcJK7Dmzmtj+pA9oO2niYgX75br7Go+vZY4UzOyViM/v6hbb
	OHHVmyDoWZ/chrxLDuftglA=
X-Google-Smtp-Source: ABdhPJx9oRg9AaRhG1GdOb5M4IdO1hFCrXJyrKjfCwfqkE9ybf2/Ag73F8a11DU89Au+9/WTsVnIsQ==
X-Received: by 2002:a05:6830:199:: with SMTP id q25mr723966ota.275.1614249266967;
        Thu, 25 Feb 2021 02:34:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:8ef:: with SMTP id d15ls1333988oic.9.gmail; Thu, 25
 Feb 2021 02:34:26 -0800 (PST)
X-Received: by 2002:a54:438f:: with SMTP id u15mr1523416oiv.60.1614249266644;
        Thu, 25 Feb 2021 02:34:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614249266; cv=none;
        d=google.com; s=arc-20160816;
        b=asLQZEwzQYBJ1Wo0Th+LF1wJ0hmuG5dw/Yf4hLWlq6GQoJ9JpJuYgXZpHrSHc6I9NN
         Fc+khVmaAo099P7eOXnHl+k3xomjbROSBWEdQwyQYgbdsPhQbW5dihiQrCvQFq4VVzLY
         wE0GogfnCNCu/imdCrdGtDYZWu8bkW/03M5jZ0Q9J0BLk9ceP2VkRdnV2gfGRQDODalI
         VMSo0rIJlGjSN4xevVW5JT6XHICVIdcQXK1clwBap1nyK8k65WUfxx/auGfQIBXtuzt+
         nGvOlcZ5KS1nNYKWkKzUrNpWEZzG1uAWseV4FAIl9+iI0fcYawya4b3UCML3pmDIc0d3
         hIzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:organization:from:references:to:subject
         :dkim-signature;
        bh=NA0XhNNgXWdKWddYRBJjHOR9CD09LFOv4oAxt+/QKh8=;
        b=nEXuw0poJC/Q+ZCB8Nc+yavYCoZpbvasi8/PrpOgzhS5zOSmK/jBIImuU9xiuk7ws9
         Qsb84Nzv4Bpf0P1ltiAj09cnY9FG55dM0GQQ93adWU+qKxu0Qdym6J/KvXhbuGni1E7K
         RDkzm8mM/12jEXON89WomzWVLqQy5Mm0hc18U0XfwhlVN+rY+hyI7ZoPIiVUcLs11251
         AjZa12Ifoj+DROHsbi+gSiLd6G6YHylG7e6PQCHmSfSdDuVZznOd/pS1lU81/QsykA7B
         ESBnG52KI8xNzCjeXHOvIbqt0xUeyRz2LXogpchMYNpRCqq+ZL/amXQtP6cmnrwJ2z3/
         4R9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=fpVtCn5Z;
       spf=pass (google.com: domain of david@redhat.com designates 63.128.21.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [63.128.21.124])
        by gmr-mx.google.com with ESMTPS id y26si445546ooy.1.2021.02.25.02.34.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 Feb 2021 02:34:26 -0800 (PST)
Received-SPF: pass (google.com: domain of david@redhat.com designates 63.128.21.124 as permitted sender) client-ip=63.128.21.124;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-464-yrGz6ss2PRqE8fSc9ob9ug-1; Thu, 25 Feb 2021 05:34:21 -0500
X-MC-Unique: yrGz6ss2PRqE8fSc9ob9ug-1
Received: from smtp.corp.redhat.com (int-mx01.intmail.prod.int.phx2.redhat.com [10.5.11.11])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 6854B19611A2;
	Thu, 25 Feb 2021 10:34:18 +0000 (UTC)
Received: from [10.36.114.58] (ovpn-114-58.ams2.redhat.com [10.36.114.58])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 658C619801;
	Thu, 25 Feb 2021 10:34:14 +0000 (UTC)
Subject: Re: [PATCH 2/3] Documentation: riscv: Add documentation that
 describes the VM layout
To: Alexandre Ghiti <alex@ghiti.fr>, Jonathan Corbet <corbet@lwn.net>,
 Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
 Arnd Bergmann <arnd@arndb.de>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-arch@vger.kernel.org, linux-mm@kvack.org
References: <20210225080453.1314-1-alex@ghiti.fr>
 <20210225080453.1314-3-alex@ghiti.fr>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat GmbH
Message-ID: <5279e97c-3841-717c-2a16-c249a61573f9@redhat.com>
Date: Thu, 25 Feb 2021 11:34:13 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.0
MIME-Version: 1.0
In-Reply-To: <20210225080453.1314-3-alex@ghiti.fr>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Scanned-By: MIMEDefang 2.79 on 10.5.11.11
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=fpVtCn5Z;
       spf=pass (google.com: domain of david@redhat.com designates
 63.128.21.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

                  |            |                  |         |> + 
ffffffc000000000 | -256    GB | ffffffc7ffffffff |   32 GB | kasan
> +   ffffffcefee00000 | -196    GB | ffffffcefeffffff |    2 MB | fixmap
> +   ffffffceff000000 | -196    GB | ffffffceffffffff |   16 MB | PCI io
> +   ffffffcf00000000 | -196    GB | ffffffcfffffffff |    4 GB | vmemmap
> +   ffffffd000000000 | -192    GB | ffffffdfffffffff |   64 GB | vmalloc/ioremap space
> +   ffffffe000000000 | -128    GB | ffffffff7fffffff |  126 GB | direct mapping of all physical memory

^ So you could never ever have more than 126 GB, correct?

I assume that's nothing new.

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5279e97c-3841-717c-2a16-c249a61573f9%40redhat.com.
