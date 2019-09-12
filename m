Return-Path: <kasan-dev+bncBC5L5P75YUERBV7V5HVQKGQE24ZSF6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A354B132C
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2019 19:05:28 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id h6sf155624wmb.2
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Sep 2019 10:05:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568307927; cv=pass;
        d=google.com; s=arc-20160816;
        b=amjuXgjZYUxK8KlTdGbNMi4hWmpK5XuWcKY/dIbWn+RZuhgZ65zW0wGcfPKyER/8ZE
         KEkPsD8oAsin8S8WaXomAh3BVa+swsQi88iZIkfQI7t+mre91Yf++kxz9lbU4s3SnoSN
         WosEny7NAyaH+uYf2yIc0kDW6p6I9tR6fn3YUiTgrJkGPo2m5kAjwjLWbDfusr0ZM3WS
         NoEPWFqzLAKOtJ+u0U53sagAp5uVYZWOsES/oM2kJ21QzTYLeRd2rftt5stbxVLh1XxG
         fsN/n/iIoWDzq6AJF+61oLPg6AJHmuOMt2ACNUxb/r6cDLc5HaGILnBs91QrE6fzHAxl
         y8ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=2jAhxQdgaGAeenU7YvroWL9NjeViykLk5l7lGEQ2wE8=;
        b=lMAJH6PC3zaTn/hBfGO1Cw57lHbe6Jq42NY4b5Z7aAgNUQv7Po8KhqIUq8sInQ6qa+
         ZISlZghAgdOsL9fNjKZKZvUQyAgFD/L8sDhL+BRGmZ59bMnoESIsLp3Km7fe08EY9wcT
         PIkqblWgxspAIs8IqrRHnq9ci32AYoibvS7VM0s3CH9tOO/5LNq6aIl9NNalY5lUvrxB
         ndZWiJtaMdwbpzs3geepmwtcqDayMXdGLofZ51e8BaS0yIV4dCCM1bCYl7bD7dpbaPWZ
         beGDx4Hr2SzFeemxIxlZPQyuba8iXV8tT+RFyDEw/egwukoU2dzqfLrMdZvwL+ZzOHNk
         LrdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2jAhxQdgaGAeenU7YvroWL9NjeViykLk5l7lGEQ2wE8=;
        b=Xys/MY6OGYiDlJtdH87ZJaYxxVPm6KA762j6V07kd5BwMP4TFM86hoE7GI7ISKcV0j
         yKcBVOjQijmNB8SrDd1qiz8Tx7dzl04SeaTkgv751ukQ6g0wg5YZcdkqhRhuVgaQGFs/
         Aiytfv0IdmsoBMGlj+U2ovTevdJWI+6Er2NhZx0CeI13IBRjv5ICEYwS+vuHFiX3KjKa
         MRxEW2/bfELiifddV8cH5dDVnbOI4mJRj9erKhhN5Sld0MdvTwy1KOy40YFljxdADOtP
         67EZR1m1MXnFlsM+OWC6iMxP8k9/QJhoQB90NEJRsiTynqgr8LxexNtKRLkoVOisAkRY
         K7aQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2jAhxQdgaGAeenU7YvroWL9NjeViykLk5l7lGEQ2wE8=;
        b=aLd65i55K8l99jUTHIoPLRDnEiHWryX7eTxL3uWHMKuMw8qw4E1Ms0H/btsfZQD7tS
         XoWHpIuJHQBTp7cqqfF2Yl4QJ+3t7NanQrlnkO83NsoO/Es/mewaxSFMNpvnRi0WS3jm
         KGUHatNcSxMgyHkFOxh+Zv/uhnJ7FnpYY7DCdmpMJv7oWuw/k3SSRgZoPB5xbu2LGSos
         zUkG6Uazu//khgyQ0xrm8cNmNYLDXcfRm5NNzADFJILrqDZ47JlASjjPa/JY4S7gaqhU
         p8RsdPcuzSUMigDsLRuW7r1w1uMYXHhQqBbtfEMrJueV2dVmTPk22fs32Oz+DWvKWdPS
         ZdZw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV4HTXs7RLMh0l/voQnTl96oAcf2DrJQcb1P4FUIFfwTQ/xGCht
	aFu1YTegFR5pM5ROQOKC2hU=
X-Google-Smtp-Source: APXvYqzfpaDa+VG7tgCBQqsPpXDiwSu/4DXDkbu1nCZjOcmNo5tESsrZKIYq7cqBL0rKWoZP8wWeUQ==
X-Received: by 2002:a1c:c00e:: with SMTP id q14mr923540wmf.14.1568307927863;
        Thu, 12 Sep 2019 10:05:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eb44:: with SMTP id u4ls7561564wrn.2.gmail; Thu, 12 Sep
 2019 10:05:27 -0700 (PDT)
X-Received: by 2002:adf:e591:: with SMTP id l17mr36232612wrm.199.1568307927336;
        Thu, 12 Sep 2019 10:05:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568307927; cv=none;
        d=google.com; s=arc-20160816;
        b=TYQQNbo2cCwAhes6XmvFB9L/aLSKF0/zEHmxbsly5/efed6eFcA16ieFxtItzitkAm
         gmuZ4hBCwNAHIOgoAywMGnDtt8bfvYLJU9rJj/gQ0TYvPukI5vRbsYJwyLw1bghnRjsP
         UAz8Xxl/8dQjNe/RJJ1ctGw55qanwyl8bhODepmKSCNwW8e6cTxszDKNnA1Vc/IEZKjh
         Ns1H8vlsLGmP3+yR9zp96oP0WKJuJYEbWrkN8OavqvZVUulgk7SEmXVAhJIhrqRDmOwM
         PVpsVK6jVc9JX0GsvACVib6WcJkczKk0z7M1igiom2y594T9R5DOLW8wwQSXkkNXW39i
         FgUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Cvs/wNDs1fsD5LJAuTOY5EA3GAOI+EM5Ngxf/tA6BC4=;
        b=B46h6sK0PTZXj3g5h8UjiyjSUJDqizYz5KvkFuNKk/4h7nsFYTTLNVZDrWXacVYTrG
         Y5lG28EFwLCv9v5VBKXlKfhtq7A3er1YK38jas/3LkKpBS5nkTluqEyikKpnxfPsg8QE
         /BNbgaIxhq1T8Y1GKXidkknzZKGBBrmmTm2GLXYzaNTDgnkl9i9B06Z4mYRdUbUbXuoR
         YKWpnuaf7pIeK3ZX6oc/y56tFpxb61fa1RQuEjNkFtFNX31FowRUTcpWwIroWFQ9FE22
         3zudoter36bDJCk96uj13nWiVuGzZltHY7iGmkFri43L11dpRdN6k9dYBwIEklZuQOdv
         rOpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id m6si31864wmc.0.2019.09.12.10.05.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Sep 2019 10:05:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.5]
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1i8SWx-0001JP-U8; Thu, 12 Sep 2019 20:05:16 +0300
Subject: Re: [PATCH v3] mm/kasan: dump alloc and free stack for page allocator
To: Vlastimil Babka <vbabka@suse.cz>, Walter Wu <walter-zh.wu@mediatek.com>
Cc: Qian Cai <cai@lca.pw>, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
 <matthias.bgg@gmail.com>, Andrew Morton <akpm@linux-foundation.org>,
 Martin Schwidefsky <schwidefsky@de.ibm.com>,
 Andrey Konovalov <andreyknvl@google.com>, Arnd Bergmann <arnd@arndb.de>,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org,
 linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com
References: <20190911083921.4158-1-walter-zh.wu@mediatek.com>
 <5E358F4B-552C-4542-9655-E01C7B754F14@lca.pw>
 <c4d2518f-4813-c941-6f47-73897f420517@suse.cz>
 <1568297308.19040.5.camel@mtksdccf07>
 <613f9f23-c7f0-871f-fe13-930c35ef3105@suse.cz>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <79fede05-735b-8477-c273-f34db93fd72b@virtuozzo.com>
Date: Thu, 12 Sep 2019 20:05:14 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <613f9f23-c7f0-871f-fe13-930c35ef3105@suse.cz>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 9/12/19 5:31 PM, Vlastimil Babka wrote:
> On 9/12/19 4:08 PM, Walter Wu wrote:
>>
>>> =C2=A0 extern void __reset_page_owner(struct page *page, unsigned int o=
rder);
>>> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
>>> index 6c9682ce0254..dc560c7562e8 100644
>>> --- a/lib/Kconfig.kasan
>>> +++ b/lib/Kconfig.kasan
>>> @@ -41,6 +41,8 @@ config KASAN_GENERIC
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select SLUB_DEBUG if SLUB
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select CONSTRUCTORS
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select STACKDEPOT
>>> +=C2=A0=C2=A0=C2=A0 select PAGE_OWNER
>>> +=C2=A0=C2=A0=C2=A0 select PAGE_OWNER_FREE_STACK
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 help
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Enables generic KASAN mode.
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Supported in both GCC and Cl=
ang. With GCC it requires version 4.9.2
>>> @@ -63,6 +65,8 @@ config KASAN_SW_TAGS
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select SLUB_DEBUG if SLUB
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select CONSTRUCTORS
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 select STACKDEPOT
>>> +=C2=A0=C2=A0=C2=A0 select PAGE_OWNER
>>> +=C2=A0=C2=A0=C2=A0 select PAGE_OWNER_FREE_STACK
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 help
>>
>> What is the difference between PAGE_OWNER+PAGE_OWNER_FREE_STACK and
>> DEBUG_PAGEALLOC?
>=20
> Same memory usage, but debug_pagealloc means also extra checks and restri=
cting memory access to freed pages to catch UAF.
>=20
>> If you directly enable PAGE_OWNER+PAGE_OWNER_FREE_STACK
>> PAGE_OWNER_FREE_STACK,don't you think low-memory device to want to use
>> KASAN?
>=20
> OK, so it should be optional? But I think it's enough to distinguish no P=
AGE_OWNER at all, and PAGE_OWNER+PAGE_OWNER_FREE_STACK together - I don't s=
ee much point in PAGE_OWNER only for this kind of debugging.
>=20
> So how about this? KASAN wouldn't select PAGE_OWNER* but it would be reco=
mmended in the help+docs. When PAGE_OWNER and KASAN are selected by user, P=
AGE_OWNER_FREE_STACK gets also selected, and both will be also runtime enab=
led without explicit page_owner=3Don.
> I mostly want to avoid another boot-time option for enabling PAGE_OWNER_F=
REE_STACK.
> Would that be enough flexibility for low-memory devices vs full-fledged d=
ebugging?

Originally I thought that with you patch users still can disable page_owner=
 via "page_owner=3Doff" boot param.
But now I realized that this won't work. I think it should work, we should =
allow users to disable it.



Or another alternative option (and actually easier one to implement), leave=
 PAGE_OWNER as is (no "select"s in Kconfigs)
Make PAGE_OWNER_FREE_STACK like this:

+config PAGE_OWNER_FREE_STACK
+	def_bool KASAN || DEBUG_PAGEALLOC
+	depends on PAGE_OWNER
+

So, users that want alloc/free stack will have to enable CONFIG_PAGE_OWNER=
=3Dy and add page_owner=3Don to boot cmdline.


Basically the difference between these alternative is whether we enable pag=
e_owner by default or not. But there is always a possibility to disable it.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/79fede05-735b-8477-c273-f34db93fd72b%40virtuozzo.com.
