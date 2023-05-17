Return-Path: <kasan-dev+bncBC32535MUICBBINBSKRQMGQEZ64ITOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id E4F5A7062E0
	for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 10:30:26 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-6237e3d5983sf7481946d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 01:30:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684312226; cv=pass;
        d=google.com; s=arc-20160816;
        b=NB2UIkiyqgNXU73Rai9c6xj+ycvFJbO/gN1PHArCPBlLFaBSwr8NprkiuOROOliEvC
         kScvl93Gtr2lg+rAu+oP/zYEqUpEwxlSXbsR+jNv4qw7Nw4b6emEDkVD+WsmUl5opD87
         cqH31+oYUC2uM155FZCqEA2RN5cQ0e7236ZJDsL0N7pC8G2KWl1Ef9hmfEQByyvgLgGk
         ZEGCJIIOUdYJFbfoX81P+8NFvOKqveQNLPjXu6DLZ1aHgH3fTUaE5awikNlgKLbQ2yYY
         Mmqs0H7k7Ff8WBZone6PAUqY2C6YSY1C5X4h4dG52NDinXlSxwTmvdTOH36RihNdN1F2
         frbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :organization:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=Ld+AvCd3BWLF3lHjONsEcF4zj7vHzlhEYxkvUntQ/oo=;
        b=GnEhX/uCSc71098mC2KT9SgKXd721ncPVcJAt5ZuViIuO2jSB2lLg59Gk3oqbfS+Uy
         eGyft2Sy49f5XB6B1MDPIDl4733anmp/imA/TkTf2NfYqZmn7IiX8e57zohjScXM5iJ0
         QJyzVgedomMQE5vVYahRpgS0wtwLE9AQc+RwuFwF0brAWrEorfGgGR24KzmNfIEIRlTv
         WFtyIEJP33Zn60oEaKaoUO7ql+GZfb7KxzUZbc5rlAppx8sKwpO6X3WB7LDGBcQlVwPf
         BP+h65knvKaDfdybr+uobn8cLOsUhsM2zpPTcA61eSNh1ASvIIruf3BYbkvclrt7WD3U
         ZY5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QmrmO1VS;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684312226; x=1686904226;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-language:in-reply-to:organization:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Ld+AvCd3BWLF3lHjONsEcF4zj7vHzlhEYxkvUntQ/oo=;
        b=Ap7BTDmIiIgoQFudeadVrp6hsP/A0vrCvI06Sea9CJuQq/k1g8nUSHR6raLdBcSECS
         YxoyHhc2UnyifNLkKmIhELlC4mLAv/vg8EH9dGBzB6YJunHeAA6EUCPlZXJOpygvL4wl
         7KK/8OcJCvvESKjHuJuLwcFKVJjnZFH986pIZV6gtWuR/WNRtfVxRq7O0K9qa4eRvbCC
         I18OFo1DQbzLPmgz+iaBr6NEttW64ZZ1dG7VajpRr/ntHMC5GINiCS7w46l1b3aV5+7K
         u2P+vx3N7SeIA7L2xT5AO9Tcn5F3F3myrtwwEbd4ViI2DizR7piTGtc8yJE+M9WDe9G+
         YmNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684312226; x=1686904226;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:organization:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ld+AvCd3BWLF3lHjONsEcF4zj7vHzlhEYxkvUntQ/oo=;
        b=Yu8qCk3W4Ilx86mR9my44GU7nFPR2EV3hqNSGo48ZvQExB/L4ZRHf86mcXTHcmdqg5
         AQnpv6clrLtn+4xserj3Um+uigEPAhta6aZeXCklduBo4mqro/rPCQ0xPK4NO4l8Rj2e
         6iG6AnVe8MiZzAvs5D+VMAXoxXauqPjA3BNkNrQjKDR12/pGX7uadQ1yjqU/GItjkQR7
         Ib2659eKTzihfdztWaMEMmM0lZkUpvpsBstvUJuaVZ9viIuXhZ1SPDugj4fO0qZGM9TG
         IFJTtRpP+aw6Dl0jz0BYsFTiVm2PDAwVLUjK8Chruu9ALzk42Ubgj0sUb7TYXyUHULe6
         bwMQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDx9k0V9srLUGQVllZJ8ewZfdE+PfLhSwtXUkNQcwMXvnF2PbTa5
	KDZjN3i7/GOSWrGp63wxNDI=
X-Google-Smtp-Source: ACHHUZ6xoFHKfGnd0ct2zOXZq4IFMU6Exw32iz5ApUDd0MHbYRLfOW6J6GvehvLRXnx+7ASfjixk6A==
X-Received: by 2002:ad4:4e09:0:b0:61b:5ea2:49fe with SMTP id dl9-20020ad44e09000000b0061b5ea249femr7321250qvb.8.1684312225787;
        Wed, 17 May 2023 01:30:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:448d:b0:61b:6d85:fa61 with SMTP id
 on13-20020a056214448d00b0061b6d85fa61ls18017qvb.3.-pod-prod-gmail; Wed, 17
 May 2023 01:30:25 -0700 (PDT)
X-Received: by 2002:ad4:5bc8:0:b0:61b:6a71:e741 with SMTP id t8-20020ad45bc8000000b0061b6a71e741mr62714768qvt.23.1684312225131;
        Wed, 17 May 2023 01:30:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684312225; cv=none;
        d=google.com; s=arc-20160816;
        b=pwMl4O1QFpoZS++D0ysesA37/OcV/gda3pfVIL/NEpPNmOEBHJBJ06sYBi1eXkdP0V
         kfyg6y+hjOSJ0D9Tg9kEahOZmvud7zWPEWysSh1xqBLWdJjyDyMMR8Z8u/5ZuzPQKQyv
         zQkRt41qSwJXvfFV3Ruu6ND81luWc4gZOvK6EkR0fgheN8f7rEJVX96u98/ZXFPJFRNF
         ufsJBO+l/WLnjk6Ntn62fRYllgXIGAvyQ1rapRyq5GI9H4Ct8TLJbyISjiumoo8hYEys
         qffsA3tSJqBcP4ThiQqNekd29As/X3qtDK4SYNQRYVHSZQ4kP0Vgxax2+6KicOXrwlqJ
         g6Yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:organization
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=lCs/dUVErnBMZp0vS+8RY4FN1qN1vupcxjp7vnWl9AY=;
        b=d/yZ5lq98t+wk/nztM8YV9xgoshHdsjABbmN5ib91bL09ZyQHVh7YNT7smA6HejvBn
         vRKVtF4zPel2a/2paGAbgaFlIK4pZSaIGfVQ19RuwOUOkXrLAkw78i13JaFwXvVv9++4
         dfhbnn78zwgx+InGz1wutaFqPQz8l53YeC7BbBzeu8Js1wJx7o5i59L9fnP7pElicOOD
         bj2JWsC5ftYYchugEWPmz6TNufdp8Y39p/cfYUpvmeukoOiXekTD9waiBUGqUqySS5/D
         bM/uShYe+/yCV9hb8LROPpcH70Q4Z+mVovfT91dbywTzAsEoiNZZbENlrEQvRN6vzMqy
         V4CA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QmrmO1VS;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id lv5-20020a056214578500b006238adde012si10402qvb.0.2023.05.17.01.30.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 May 2023 01:30:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-601-1rNuODe_O4q_6QW-d1svOA-1; Wed, 17 May 2023 04:30:23 -0400
X-MC-Unique: 1rNuODe_O4q_6QW-d1svOA-1
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-3f433a2308bso39900865e9.0
        for <kasan-dev@googlegroups.com>; Wed, 17 May 2023 01:30:23 -0700 (PDT)
X-Received: by 2002:a05:600c:2216:b0:3f4:2a69:409 with SMTP id z22-20020a05600c221600b003f42a690409mr1004162wml.11.1684312222178;
        Wed, 17 May 2023 01:30:22 -0700 (PDT)
X-Received: by 2002:a05:600c:2216:b0:3f4:2a69:409 with SMTP id z22-20020a05600c221600b003f42a690409mr1004132wml.11.1684312221771;
        Wed, 17 May 2023 01:30:21 -0700 (PDT)
Received: from ?IPV6:2003:cb:c707:3900:757e:83f8:a99d:41ae? (p200300cbc7073900757e83f8a99d41ae.dip0.t-ipconnect.de. [2003:cb:c707:3900:757e:83f8:a99d:41ae])
        by smtp.gmail.com with ESMTPSA id l8-20020a1c7908000000b003f506e6ff83sm1421875wme.22.2023.05.17.01.30.20
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 May 2023 01:30:21 -0700 (PDT)
Message-ID: <c9f1fc7c-62a2-4768-7992-52e34ec36d0f@redhat.com>
Date: Wed, 17 May 2023 10:30:19 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.11.0
Subject: Re: [PATCH 1/3] mm: Move arch_do_swap_page() call to before
 swap_free()
To: Peter Collingbourne <pcc@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
 =?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, "surenb@google.com" <surenb@google.com>,
 =?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?=
 <chinwen.chang@mediatek.com>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 =?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?=
 <Kuan-Ying.Lee@mediatek.com>, =?UTF-8?B?Q2FzcGVyIExpICjmnY7kuK3mpq4p?=
 <casper.li@mediatek.com>,
 "gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
 vincenzo.frascino@arm.com, Alexandru Elisei <alexandru.elisei@arm.com>,
 will@kernel.org, eugenis@google.com, Steven Price <steven.price@arm.com>,
 stable@vger.kernel.org
References: <20230512235755.1589034-1-pcc@google.com>
 <20230512235755.1589034-2-pcc@google.com>
 <7471013e-4afb-e445-5985-2441155fc82c@redhat.com> <ZGJtJobLrBg3PtHm@arm.com>
 <ZGLC0T32sgVkG5kX@google.com>
 <851940cd-64f1-9e59-3de9-b50701a99281@redhat.com>
 <CAMn1gO79e+v3ceNY0YfwrYTvU1monKWmTedXsYjtucmM7s=MVA@mail.gmail.com>
From: David Hildenbrand <david@redhat.com>
Organization: Red Hat
In-Reply-To: <CAMn1gO79e+v3ceNY0YfwrYTvU1monKWmTedXsYjtucmM7s=MVA@mail.gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=QmrmO1VS;
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

>> Would the idea be to fail swap_readpage() on the one that comes last,
>> simply retrying to lookup the page?
> 
> The idea would be that T2's arch_swap_readpage() could potentially not
> find tags if it ran after swap_free(), so T2 would produce a page
> without restored tags. But that wouldn't matter, because T1 reaching
> swap_free() means that T2 will follow the goto at [1] after waiting
> for T1 to unlock at [2], and T2's page will be discarded.

Ah, right.

> 
>> This might be a naive question, but how does MTE play along with shared
>> anonymous pages?
> 
> It should work fine. shmem_writepage() calls swap_writepage() which
> calls arch_prepare_to_swap() to write the tags. And
> shmem_swapin_folio() has a call to arch_swap_restore() to restore
> them.

Sorry, I meant actual anonymous memory pages, not shmem. Like, anonymous 
pages that are COW-shared due to fork() or KSM.

How does MTE, in general, interact with that? Assume one process ends up 
modifying the tags ... and the page is COW-shared with a different 
process that should not observe these tag modifications.

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c9f1fc7c-62a2-4768-7992-52e34ec36d0f%40redhat.com.
