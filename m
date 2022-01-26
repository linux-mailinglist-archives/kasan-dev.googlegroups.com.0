Return-Path: <kasan-dev+bncBAABBHHUYSHQMGQEC27KCKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 1727549C952
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jan 2022 13:10:06 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id a4-20020a9d5c84000000b005a1daff4564sf578124oti.2
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jan 2022 04:10:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643199005; cv=pass;
        d=google.com; s=arc-20160816;
        b=k0QxJ5yovPZ/4U3iUwbv+BEZBkp9RjkG+VPtXoFDdwPENmlHATldfWdSLDfs8T8p7m
         tbhTFU/FYWXp0VDku6Vym9aA6n0FjJAoelxovCwhWZveNY+ytGA94yeEUEoVSnFQ4JK2
         U54BB4YYfxVFDi++gOQn72oti7wj5N42dUp9NaOr1mOI24S2blmoGqr7vw0T/FaAdKtv
         CP6l4zDCZ7+mwN/SOcMQIAhQayTTpN66Bq0og7yyJuSvbchlzHgTsyP0fhoEGd8U0lxq
         lq9C7cVqrd8Yf6XtX1gc2pq0axZ01FRmHNz+aVEJPL2XsHQqTKKJMguSVOXosbjc6kqx
         3uBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=3apKhLjvKZYnTP8/rzZDiterJOLycBoSZQEQZxdQTjo=;
        b=XEg/y+t6EIYTRgoBYRQwA3W9OTxdAFANbBPUtI3m1A6fIWvIWdXb8oIqZPUOo1VT6Q
         9F2g5PX6Q0juAJqX6TJHkhLDc+L5lftwYFj7Ar9swwf+aktWR9tDfQHy8mBFpzahEKSY
         b9GVbMgOp/o8hdOLvVw8Fj4gec45VwF+fXG4/0cdfUksviV1b/BFXjOCrYs58qtX/M4H
         JK0fkJFO+ZWq3pTZ231d7DWYjJbC02Ouc7Lf4bybk/1mIdaGCA8gjhqy/UvxNlGWOjZz
         I1mH9MiP0q1SzncejjLjjBo6XhNsqkwepchaB3sTLVTLPlq7xvbv/l7HEi+DFj3ljabH
         hG0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=message-id:date:mime-version:user-agent:subject:content-language:to
         :cc:references:from:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=3apKhLjvKZYnTP8/rzZDiterJOLycBoSZQEQZxdQTjo=;
        b=UUcaEXNzx1O1Ty6Jo0dFNthqQ7T/uSzyDY9CjW1ZIPT9tuO/ne6ltPOCUB56x10seY
         x8dyRB+Z9L28XyByhgl4W1GzTx8E1AgQiuU8zDSvAG3seh36isEPoLB5/3LTA96ln/am
         3dp1pUqEXcpb1o8fGGcoaBBliB2oGuFa0LBby2KFu8STa/08he1AwdIPa5NqZxearI7W
         yWgaLBKu2kKOoXz8C40dlkzyMvBpyHOBeunLj7ZiJ/5zGViug9NQSGSuXwamRoBWGzmn
         n4tVbq/m4Z/A2fm/NdiAnWQbCrZSLZbQ61Uq3JWc3IDoVy7Ntgrle9yNeY0q/j9hGBFx
         VsWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3apKhLjvKZYnTP8/rzZDiterJOLycBoSZQEQZxdQTjo=;
        b=mL4xWZKCNQcis6sRe6iHRzKPTyEWWzcvQB8aLPo0eJHdCH1Vll/eCHMRCvkOpztSP3
         Mu7zd0JK6Vmv7ihCYbiUdYnRpIwK5B6B0sSaSs7QJcayObv8p4akrrjEcvNeBePkw+4d
         v8Rdwm9Gu5H4pkxvyCpIkE/Dfb9XXJwf+30wrrvEkW9CRCwFPZLon9PdHLjR+4c8HC1d
         bdNq5MXFdRqs1MYVm+82IOJ8S+wjQxIj0ghehVuFQweN2y/UWy0m8zpBnAC5iLDpDJSk
         DEUn5gwq3Egra8nXZocweIfBXlR9lZjNw9dA36aGFXw+GWx2OZognNFgQ1MtB6ELKcHe
         vrDw==
X-Gm-Message-State: AOAM530i9OO5MVjmbAxXs4IUl6/aRnqywcLlVLG6pF7Nsdlm7Eij0Ygn
	iipH89c3oQsaM0NyJPd45wM=
X-Google-Smtp-Source: ABdhPJz6rmRA946n4n/UUb1sH31R2aP/82NMPEqzKc3Kh2a15O2cTYYD2QRPM8Srxklrun2r7qgMUA==
X-Received: by 2002:a05:6830:1e99:: with SMTP id n25mr16498373otr.344.1643199004645;
        Wed, 26 Jan 2022 04:10:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:e84:: with SMTP id k4ls725707oil.9.gmail; Wed, 26
 Jan 2022 04:10:03 -0800 (PST)
X-Received: by 2002:a05:6808:221d:: with SMTP id bd29mr3691373oib.233.1643199002872;
        Wed, 26 Jan 2022 04:10:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643199002; cv=none;
        d=google.com; s=arc-20160816;
        b=VA679VfohjIS1DtjCM4QEZ+Eoc2PG6Hm+5uUJfwxdUW97Oaz1/QlKteM2ZrGOfX0gI
         MZuJDVpPU+DdNtskS5fJ4Mz7EfXu8ZdD3z+LIoiThZ5f3sUk32cYj31oThhQJWwaBe24
         U3DJvAhgX16LYs5uSwa94IT2dJHVAGxjzjxBJB/T9dYC3BN1KBAofDuuHWxQ/kGls664
         n48g1qSQ5WhvnCscnF2x0/mLhjXbsMZhMCjJ32h2ToInt6qR456N1Vt1QwYRvSytagZC
         wmRSPmnCEPIbBvfnb3lEeHRCgOjZvOPrcTdQn87W5w9RcCfub+0dD9K/i1DT/SiVkOY3
         79CQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id;
        bh=PQ6CapKmKAwz7zhH74C5Rq/VA9D7PShhhu+2RdPV+2o=;
        b=adEiFXaHZIyzUD/kT9w/F0UJRKaXpjQTzVTQ28wu3Bz2sT3TDNviItPYMI/BR9KO2r
         uTuwMysvo3rSbBGHX/Kjct3YvXCFyKkiB7QvQpTFTN8vMC+ucH3CSicod1GaOI/KAyRN
         XdnUsdQepOk/pTjBlRtJZOG2vF4TAUiv2O+99z/P4jZSNdrcnvSM0LRE877Fv0IXZtu3
         WYN7iLPL/j2I3cWNR8N+ZqOlB2TtlFAfJxBL1c/6PXsEg94p0JSlIwjALumEJAilj+WA
         Y0di1mp6Co75trYX+lofpktbninEgMAy4lRNJv69Pv0Jk0bBWOrP18aeI2txL2zvZvBN
         YeHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id u25si659122otj.4.2022.01.26.04.10.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 26 Jan 2022 04:10:02 -0800 (PST)
Received-SPF: pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from kwepemi100010.china.huawei.com (unknown [172.30.72.56])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4JkMrF2qH4zZfM0;
	Wed, 26 Jan 2022 20:06:05 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (7.193.23.234) by
 kwepemi100010.china.huawei.com (7.221.188.54) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Wed, 26 Jan 2022 20:09:59 +0800
Received: from [10.174.179.19] (10.174.179.19) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Wed, 26 Jan 2022 20:09:59 +0800
Content-Type: multipart/alternative;
	boundary="------------0r5L9YsFuj0bn5CuUOBFgq1q"
Message-ID: <1e219dd7-c2d0-1d1f-f662-2002311adef6@huawei.com>
Date: Wed, 26 Jan 2022 20:09:58 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.3.2
Subject: Re: [PATCH RFC 1/3] kfence: Add a module parameter to adjust kfence
 objects
Content-Language: en-US
To: Marco Elver <elver@google.com>
CC: <glider@google.com>, <dvyukov@google.com>, <corbet@lwn.net>,
	<sumit.semwal@linaro.org>, <christian.koenig@amd.com>,
	<akpm@linux-foundation.org>, <kasan-dev@googlegroups.com>,
	<linux-doc@vger.kernel.org>, <linux-kernel@vger.kernel.org>,
	<linaro-mm-sig@lists.linaro.org>, <linux-mm@kvack.org>
References: <20220124025205.329752-1-liupeng256@huawei.com>
 <20220124025205.329752-2-liupeng256@huawei.com>
 <Ye5hKItk3j7arjaI@elver.google.com>
 <6eb16a68-9a56-7aea-3dd6-bd719a9ce700@huawei.com>
 <CANpmjNM_bp03RvWYr+PaOxx0DS3LryChweG90QXci3iBgzW4wQ@mail.gmail.com>
 <CANpmjNO8g_MB-5T9YxLKHOe=Mo8AWTmSFGh5jmr479s=j-v0Pg@mail.gmail.com>
From: "'liupeng (DM)' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CANpmjNO8g_MB-5T9YxLKHOe=Mo8AWTmSFGh5jmr479s=j-v0Pg@mail.gmail.com>
X-Originating-IP: [10.174.179.19]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-CFilter-Loop: Reflected
X-Original-Sender: liupeng256@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liupeng256@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=liupeng256@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: "liupeng (DM)" <liupeng256@huawei.com>
Reply-To: "liupeng (DM)" <liupeng256@huawei.com>
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

--------------0r5L9YsFuj0bn5CuUOBFgq1q
Content-Type: text/plain; charset="UTF-8"; format=flowed

On 2022/1/24 19:55, Marco Elver wrote:
> On Mon, 24 Jan 2022 at 12:45, Marco Elver<elver@google.com>  wrote:
>> [ FYI, your reply was not plain text, so LKML may have rejected it. I
>> advise that you switch your email client for LKML emails to plain
>> text. ]
>>
>> On Mon, 24 Jan 2022 at 12:24, liupeng (DM)<liupeng256@huawei.com>  wrote:
>> [...]
>>>> I think the only reasonable way forward is if you add immediate patching
>>>> support to the kernel as the "Note" suggests.
>>> May you give us more details about "immediate patching"?
>> [...]
>>> Thank you for your patient suggestions, it's actually helpful and inspired.
>>> We have integrated your latest work "skipping already covered allocations",
>>> and will do more experiments about KFENCE. Finally, we really hope you can
>>> give us more introductions about "immediate patching".
>> "Immediate patching" would, similar to "static branches" or
>> "alternatives" be based on code hot patching.
>>
>> https://www.kernel.org/doc/html/latest/staging/static-keys.html
>>
>> "Patching immediates" would essentially patch the immediate operands
>> of certain (limited) instructions. I think designing this properly to
>> work across various architectures (like static_keys/jump_label) is
>> very complex. So it may not be a viable near-term option.
>>
>> What Dmitry suggests using a constant virtual address carveout is more
>> realistic. But this means having to discuss with arch maintainers
>> which virtual address ranges can be reserved. The nice thing about
>> just relying on memblock and nothing else is that it is very portable
>> and simple. You can have a look at how KASAN deals with organizing its
>> shadow memory if you are interested.
> Hmm, there may be more issues lurking here:
>
> https://lore.kernel.org/all/20200929140226.GB53442@C02TD0UTHF1T.local/
> https://lore.kernel.org/all/20200929142411.GC53442@C02TD0UTHF1T.local/
>
> ... and I'm guessing if we assign a fixed virtual address range it'll
> live outside the linear mapping, which is likely to break certain
> requirements of kmalloc()'d allocations in certain situations (a
> problem we had with v1 of KFENCE on arm64).
>
> So I don't even know if that's feasible. :-/
>
> Thanks,
> -- Marco
> .

Thank you very much, we will try the suggestions you give.

Thanks,
-- Peng Liu
.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1e219dd7-c2d0-1d1f-f662-2002311adef6%40huawei.com.

--------------0r5L9YsFuj0bn5CuUOBFgq1q
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html>
  <head>
    <meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3DUTF-8=
">
  </head>
  <body>
    <div class=3D"moz-cite-prefix">On 2022/1/24 19:55, Marco Elver wrote:<b=
r>
    </div>
    <blockquote type=3D"cite"
cite=3D"mid:CANpmjNO8g_MB-5T9YxLKHOe=3DMo8AWTmSFGh5jmr479s=3Dj-v0Pg@mail.gm=
ail.com">
      <pre class=3D"moz-quote-pre" wrap=3D"">On Mon, 24 Jan 2022 at 12:45, =
Marco Elver <a class=3D"moz-txt-link-rfc2396E" href=3D"mailto:elver@google.=
com">&lt;elver@google.com&gt;</a> wrote:
</pre>
      <blockquote type=3D"cite">
        <pre class=3D"moz-quote-pre" wrap=3D"">
[ FYI, your reply was not plain text, so LKML may have rejected it. I
advise that you switch your email client for LKML emails to plain
text. ]

On Mon, 24 Jan 2022 at 12:24, liupeng (DM) <a class=3D"moz-txt-link-rfc2396=
E" href=3D"mailto:liupeng256@huawei.com">&lt;liupeng256@huawei.com&gt;</a> =
wrote:
[...]
</pre>
        <blockquote type=3D"cite">
          <blockquote type=3D"cite">
            <pre class=3D"moz-quote-pre" wrap=3D"">I think the only reasona=
ble way forward is if you add immediate patching
support to the kernel as the "Note" suggests.
</pre>
          </blockquote>
          <pre class=3D"moz-quote-pre" wrap=3D"">
May you give us more details about "immediate patching"?
</pre>
        </blockquote>
        <pre class=3D"moz-quote-pre" wrap=3D"">[...]
</pre>
        <blockquote type=3D"cite">
          <pre class=3D"moz-quote-pre" wrap=3D"">Thank you for your patient=
 suggestions, it's actually helpful and inspired.
We have integrated your latest work "skipping already covered allocations",
and will do more experiments about KFENCE. Finally, we really hope you can
give us more introductions about "immediate patching".
</pre>
        </blockquote>
        <pre class=3D"moz-quote-pre" wrap=3D"">
"Immediate patching" would, similar to "static branches" or
"alternatives" be based on code hot patching.

<a class=3D"moz-txt-link-freetext" href=3D"https://www.kernel.org/doc/html/=
latest/staging/static-keys.html">https://www.kernel.org/doc/html/latest/sta=
ging/static-keys.html</a>

"Patching immediates" would essentially patch the immediate operands
of certain (limited) instructions. I think designing this properly to
work across various architectures (like static_keys/jump_label) is
very complex. So it may not be a viable near-term option.

What Dmitry suggests using a constant virtual address carveout is more
realistic. But this means having to discuss with arch maintainers
which virtual address ranges can be reserved. The nice thing about
just relying on memblock and nothing else is that it is very portable
and simple. You can have a look at how KASAN deals with organizing its
shadow memory if you are interested.
</pre>
      </blockquote>
      <pre class=3D"moz-quote-pre" wrap=3D"">
Hmm, there may be more issues lurking here:

<a class=3D"moz-txt-link-freetext" href=3D"https://lore.kernel.org/all/2020=
0929140226.GB53442@C02TD0UTHF1T.local/">https://lore.kernel.org/all/2020092=
9140226.GB53442@C02TD0UTHF1T.local/</a>
<a class=3D"moz-txt-link-freetext" href=3D"https://lore.kernel.org/all/2020=
0929142411.GC53442@C02TD0UTHF1T.local/">https://lore.kernel.org/all/2020092=
9142411.GC53442@C02TD0UTHF1T.local/</a>

... and I'm guessing if we assign a fixed virtual address range it'll
live outside the linear mapping, which is likely to break certain
requirements of kmalloc()'d allocations in certain situations (a
problem we had with v1 of KFENCE on arm64).

So I don't even know if that's feasible. :-/

Thanks,
-- Marco
.</pre>
    </blockquote>
    <pre>Thank you very much, we will try the suggestions you give.

Thanks,
-- Peng Liu
.
</pre>
  </body>
</html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/1e219dd7-c2d0-1d1f-f662-2002311adef6%40huawei.com?utm_=
medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan=
-dev/1e219dd7-c2d0-1d1f-f662-2002311adef6%40huawei.com</a>.<br />

--------------0r5L9YsFuj0bn5CuUOBFgq1q--
