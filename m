Return-Path: <kasan-dev+bncBAABBSORYHEQMGQEJLBW5BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B307CA010A
	for <lists+kasan-dev@lfdr.de>; Wed, 03 Dec 2025 17:43:55 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-37a4e2bbbc0sf30086961fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Dec 2025 08:43:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764780235; cv=pass;
        d=google.com; s=arc-20240605;
        b=eF1NUHJSAXUvJilGTJjec0NJN+WdQU93veu5YhQjO5D34hm7zEE/wYpJVl+eum2AyG
         pL+4ArovbTh37kAU8vl6grVnTgDpJVMhQgj8aOu77uYBG3Qb6MppvznOn2DdmX9AQlcI
         bH4AHRSelw1tWaezITLAGJEIeBr8iUOHqzpc/VH/ka24iCiXRk/EdhZuSMGGRv2J8M0l
         T59srp2AzFhV46r3PsFIwpXsuV2peO4xd4O6+5VhzpbWvbXU1ElqsQw3+Jo+wF0hZzMz
         GtKERsLCnHXqunrAM+y/E8YKV0SyTMPn1dvmldoNjdLLH+KSDX8qIJTtsfEHZisN7vCy
         PDHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=bbuBZjSpAN1ZCU1i02NM/q+Y/doFGdovmjrg/E/EuTw=;
        fh=1X7yO6K7tkna9t/pXfNDWC90/JtsIMoYWcYy12jX1YQ=;
        b=M8LKG7jTZ5BqWQWJMDqoI5y6PGr/taXMKuNVV41PbwxXiEAYEa+heCnj9Qp39vepHB
         Pxih3eQWL1HdMBamAaA6PNrXd2ZKO1VTL23kG2tQzIe0g6JUUkxjLOJ8xvyki3sxP1ci
         +trL8RaSE35HPooqVE45+2EpFHuiMENCwpyce4yaumo3n7rfccYMQ3TSyNom0BLU1UX2
         y1LGx2JN16qLY+eDWspWe5GTHR/CzG0NcLEZT7IL+7Kg5BYqXZNUY/Rcw/x+J/Hov39e
         QA3Vz6A0URK7K0EeS2JET1GjEWN8M6AAmHmAR6e3mZN3DHvyQCPuoAMggdd7uRsJ7TRf
         hLoA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=ChzS+WEs;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764780235; x=1765385035; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=bbuBZjSpAN1ZCU1i02NM/q+Y/doFGdovmjrg/E/EuTw=;
        b=dGc/AGNESwWY+hzOx8+87pB6k+pfsRttfY6H4CbTdJWPbDbB/KQhnZKg0OV08NPUVC
         W4mThTtG2z2iOQruIbUK/2kn0Q6FOnydPaH47RAIICoO5AUsl+WI870+g7S+QhEkoqLU
         ibPSOitXmX0sXTuFJT9rVlT1Kqj4t7lRB36SXAUdFIctDu4PKK2hw0VvcYNUeuwJc3Wv
         SdDlgxLKhE4QOYMi5jRtu0jaYmVu+UhjI9TxyEK+drze5XtxkfibS+mHg/kOWQ+QZ+u3
         AErF0wxIMgMNPN0S4LIjrgfI0ZEMuVzrPy+fBaPIfVLFR4n2eP0oZmaEXrG2DUx4Idfr
         Fn7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764780235; x=1765385035;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=bbuBZjSpAN1ZCU1i02NM/q+Y/doFGdovmjrg/E/EuTw=;
        b=Ib24PI3q/v/cAQ5sXrH6bWHjmlI3TeoGFQz/+9t1z0CAz7hpcDnSQdDVC3OTfxWZp0
         /8cLPcVo5Nrrf2tGWslqvxjXYBuj7rwnlyl876rm4mvewy+qQyaiyZZNp01G2oH2FOzO
         W6QDzHKK7v/MgNusKwAdfeCMer9nZVtfQl2s+Z3yOwjiPYuB7fW78ObThh+4+pTJHaip
         t5ZoFV0nCm0MqxgZnX6mfB5m0HY3po7O2znXUYiJeYFyvo/oyYL6n/ZZKwb9+Ju34DID
         C9Jo2Wovr6EGZgd+lIoiyh4rR9CFIjgUuA0uhlzXYMVs2LF6gRYIpi0i/Dhz5eAdqpN3
         vjMA==
X-Forwarded-Encrypted: i=2; AJvYcCVIe4pvLUFkW0XGqSskfNUY3Hs148J3Q+ZhJGxidI6Xu9gvXJCqsgVE3Co6wmwb5U1sf8lteA==@lfdr.de
X-Gm-Message-State: AOJu0YyprbTLsI+HvGKNZ38G874ELvCWHaTRF0Lx1kj6GanRwzW+DD+G
	Bx6TdCuLhX8g/a8hc7BFFb/19CRIII9CmAKXl/nR0b2GWMBFuoVd6CYV
X-Google-Smtp-Source: AGHT+IGA3RdT77wVDd3caDQ1PTn7UfXZrEGh6XLJVgXDuS1ZpClA3toYewQn92gSQTg8axmfnky7Mw==
X-Received: by 2002:a05:6512:3a96:b0:57b:5794:ccd9 with SMTP id 2adb3069b0e04-597d3f01749mr1338059e87.9.1764780234112;
        Wed, 03 Dec 2025 08:43:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZS4iiqSsn4CrG5yWS6tzhOzcWQbbUA7dh9HvQDZqsMDw=="
Received: by 2002:ac2:4f0a:0:b0:597:d4ce:7d63 with SMTP id 2adb3069b0e04-597d4ce7f62ls208945e87.1.-pod-prod-05-eu;
 Wed, 03 Dec 2025 08:43:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUoqJbNByE6AqjhV8zhN7LIhs+TeQKT+ZjWNhJk137Sj9VC/vyONttOUHE1Q5u249yljoMjv0X/19g=@googlegroups.com
X-Received: by 2002:a05:6512:2312:b0:595:7f2e:de0b with SMTP id 2adb3069b0e04-597d3f223d7mr1235633e87.12.1764780231888;
        Wed, 03 Dec 2025 08:43:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764780231; cv=none;
        d=google.com; s=arc-20240605;
        b=X42fQlpAz+WxIfy/lU4czXkkANTqZF0oIRqkKGtMtlm1vlRLsA+lyuQ9/zoWGvcTAj
         zSOiJdA2GgEpGuoxK6jWLDTOVLouRwZRa+JBSa2B6AIZUKeJwAwBrXFI16k2niMqfNqQ
         j9eVAkffml8GhEvsqHMYa+TApdYERG3naM36tNmdQIxWS9qthf3zQsEKjy1SSRni8VNp
         QsSged84RBae/5vcPsCUqiuaxFPWOYqVC5sj5EBqJ+i3fxmrr2AgkbrkhNEP0OPruuYb
         PZQSzz4+Ys5J8EtaAi6sec1DyX8PvDlqdM0DQ0P9xCN1OdQ5QKi8cJDPrnMylaHS+6MV
         V4nA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=nxrvBXGpA1Q+nnlGY6f0s+0LHNsraSWWBUdSBcXFF08=;
        fh=4K5TabfyPOy2RkvUUFCgcaaUF09Fadi1074DRI9r1A4=;
        b=awYl18vBbep87fl80RSo05aZ58f0HG2WUmIvy0EGluo5wriQ2sb+tFO02NAtzVadu0
         Dw9UZk+KBXGzN7LUDeD2dH2hHuLh/WQSU2tBLs4+WcAwlKZuX82PbascyQHaae+dRkX8
         8d+cdBxJRg4p297LpK7GezpezA7woOx+J25asC9jINplX2AJNgzm8EvDagpa5tW37y49
         j1Imimou3mRYjuwB39XUo6ahr4vXAJ03KJfmGK7DVCE6ulXyWjFAvCIVpsck9R0vkyhw
         4XDrzrSBz54jEhM8T3sKAzXW0fN4ECVQQY03LZwfZBjAJWGETUflDiigMHGQzwBI+0bw
         7TgQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=ChzS+WEs;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-10631.protonmail.ch (mail-10631.protonmail.ch. [79.135.106.31])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37d2446d6cfsi2598061fa.10.2025.12.03.08.43.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Dec 2025 08:43:51 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) client-ip=79.135.106.31;
Date: Wed, 03 Dec 2025 16:43:43 +0000
To: Andrey Konovalov <andreyknvl@gmail.com>
From: =?UTF-8?Q?=27Maciej_Wiecz=C3=B3r=2DRetman=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, Marco Elver <elver@google.com>, stable@vger.kernel.org, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH v2 1/2] kasan: Refactor pcpu kasan vmalloc unpoison
Message-ID: <bi7dif47rpmdymfu3fkuz432vv5p2tmabk5snpqo27f5fitq5x@xap7rkeqejrj>
In-Reply-To: <CA+fCnZcNoLERGmjyVV=ykD62hPRkPua4AqKE083BBm6OHmGtPw@mail.gmail.com>
References: <cover.1764685296.git.m.wieczorretman@pm.me> <3907c330d802e5b86bfe003485220de972aaac18.1764685296.git.m.wieczorretman@pm.me> <CA+fCnZcNoLERGmjyVV=ykD62hPRkPua4AqKE083BBm6OHmGtPw@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 0dd43d3234ed39ac31442c89bad75ed3613a9e3d
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=ChzS+WEs;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
Reply-To: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
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

On 2025-12-03 at 16:53:04 +0100, Andrey Konovalov wrote:
>On Tue, Dec 2, 2025 at 3:29=E2=80=AFPM Maciej Wieczor-Retman
><m.wieczorretman@pm.me> wrote:
>>
>> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>>
...
>> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
>> index d4c14359feaf..7884ea7d13f9 100644
>> --- a/mm/kasan/common.c
>> +++ b/mm/kasan/common.c
>> @@ -28,6 +28,7 @@
>>  #include <linux/string.h>
>>  #include <linux/types.h>
>>  #include <linux/bug.h>
>> +#include <linux/vmalloc.h>
>>
>>  #include "kasan.h"
>>  #include "../slab.h"
>> @@ -582,3 +583,19 @@ bool __kasan_check_byte(const void *address, unsign=
ed long ip)
>>         }
>>         return true;
>>  }
>> +
>> +#ifdef CONFIG_KASAN_VMALLOC
>> +void kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
>> +                              kasan_vmalloc_flags_t flags)
>
>kasan_unpoison_vmap_areas() needs to be defined in
>inclunde/linux/kasan.h and call __kasan_unpoison_vmap_areas() when
>kasan_enabled() =3D=3D true, similar to the other wrappers.
>
>And check my comment for patch #2: with that, you should not need to
>add so many new __helpers: just __kasan_unpoison_vmalloc and
>__kasan_unpoison_vmap_areas should suffice.

Okay, I think I see what you mean. I was trying to avoid using
__kasan_unpoison_vmalloc() here so that it compiled properly, but that
was before I added the ifdef guard. Now there is not reason not to use
it here.

I'll make the changes you mentioned.

Kind regards
Maciej Wiecz=C3=B3r-Retman

>
>> +{
>> +       unsigned long size;
>> +       void *addr;
>> +       int area;
>> +
>> +       for (area =3D 0 ; area < nr_vms ; area++) {
>> +               size =3D vms[area]->size;
>> +               addr =3D vms[area]->addr;
>> +               vms[area]->addr =3D __kasan_unpoison_vmap_areas(addr, si=
ze, flags);
>> +       }
>> +}
>> +#endif

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b=
i7dif47rpmdymfu3fkuz432vv5p2tmabk5snpqo27f5fitq5x%40xap7rkeqejrj.
