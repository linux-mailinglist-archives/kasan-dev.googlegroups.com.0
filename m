Return-Path: <kasan-dev+bncBCCMH5WKTMGRBWOKZ6ZQMGQEYPQUXOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 412B290FE7A
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 10:16:27 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id 46e09a7af769-6f9810627dasf743149a34.2
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 01:16:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718871385; cv=pass;
        d=google.com; s=arc-20160816;
        b=IMZh1JoS4AYvLwAC1Q1O7eQsAk+OQZ5RuaM/dfWI0+UMPCabJ7VL0Ep5EpxO+fYk32
         eh0SSbWFEk4KBZtfBrYHxIPB+iYVvp5RxTj9Da1qJ332Lm9K9lhekvoKPu4wqETE/RC2
         Zoeqasa2x27dw5Jzc+An/xfEBuSSj6PGhoWvufr33nT7OagiDBazn4pDz7UgL63yU2te
         qPOiFB5VDR0nWPSQLc+FvWKKQ54eakA3trCaMN+9/Y7aB8qarldd7lQKETehL0JJnOCc
         6jeg19LKU9N0CsIO07lmzTunFFTRLGTpWeWSflNs1q0AVEH2naMAnwHYaI3xGGEC7SRu
         v3Qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AbsQ128RJ/cr7PAyonBQnkCFdtj4RG+7AHwb7XmKxek=;
        fh=O0bYS+GLchRb1DapzeUGVaNzwX8FBuHO8ZuKSVuww90=;
        b=ak/dCXsVwLD/f9M9zMs5CS5xQi0xt8fJrXeXCzqLDYYt8YdgR2ttnRF4coY1rdiIyQ
         7NqDWchlR3Kaws3h2qhxbbu+A3egEfhKD2nKSLTpiKOQzdOuYrSkZhzwnxkM6RhXFJ7K
         8J6Cv5T88FJ16cKBpbtcOWZp0wruNM7lsXoSVlCCgq45Yf5W7+82oQbgOyNcVdwen/lp
         VqIqIjE6NPHzEil7HS46KfN2DrAiC68KMw8XulDg3tEhQ4yn1WVyTFJ6oTVixaB1+80B
         E2sESbBLiq3RcE6ucDU0jnBeYpIscdAmyd9pIDmtJF3I+ML1pFVuducVkDNPcD3znUGe
         YCPw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Op2ZrNsQ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718871385; x=1719476185; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AbsQ128RJ/cr7PAyonBQnkCFdtj4RG+7AHwb7XmKxek=;
        b=K+II8LPXLBbr77dxdhsNj3brEI7YnNN9HODrZrzpPNVUPaqeaRkqUW6HCElDortn4C
         K720AkbTpiCTt+hC/k1yo93U/Ip376ejzrIwU3z663Q5cIebaBnOQXWx02tGtG1VEfYc
         MFNp8zKc1SDA9k99Cj2IzSmRZ38tua3l9VwJT3rTu8nQWPAycpXh3twk6wA31oFIyEH/
         JyjNiLKYvpXBCg7ya4B6sLH83xyceqw1AZulRZCU83LkqYvda4Mz6tOGsI8ppSlMf3A3
         8cH4EDOszycFgFAy7Y5ZJUqsO/VdPcTYVIqLm9IRr8lAPTEHu9jA/VFBOLftaPaYvIko
         u//A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718871385; x=1719476185;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=AbsQ128RJ/cr7PAyonBQnkCFdtj4RG+7AHwb7XmKxek=;
        b=o2aHmITZBy5nj4zUTFUYF7Wela7bVnnvNkmpdfcY4hn4hL5YxDLrBLz0Ap9JQVQqLD
         C2W19+712kZTrIktu/a4EbikDMDNcWv0RzRPXs6kGeeYpm2S36NW/6F3pYkBJg4kTIDe
         ai7xLx8tdsyCDzbV/qH1+yu6BfIqApBJZnLE7GAPY5ztpJRwCii3BXi0502QEOCRLnT4
         nEVTYAJu9Xy2iSCBLBP5fpet8Ae3qM576qvpDaFxWY14piuUNEr1EM706fuhXFiBzjES
         8FyyOTR8ZDxcicl8MGxcJlYVGGjbFXUps0bQn6cJqQFxiKGYI/KG/j1lf10Oe33jmUIj
         3jKA==
X-Forwarded-Encrypted: i=2; AJvYcCVzKmJhP5aDrX27yWDhALO/HtAI3y7f/m3ME3Ni++l8HmXVY75RmdmqOLvqyyCuToXwZcYwrU+1UdQ0OCndQ8GSmapvbnNqWg==
X-Gm-Message-State: AOJu0YzSBvk16BjlxbO/oSF/5FF6P7j84M4Z5vB5TAHhacwn1pI8P/Pl
	3KWFJeH5m+fNPbHUosvd/jxHUP9QfJrq3QPYR8R9mZETAs1RsAMV
X-Google-Smtp-Source: AGHT+IF4GVr6EbDr/j15MHoSJOt3Xmduj4TIEv9z0xLXzyEP2BF2+vC+hkfHMmFIu4BspXseJnVvyA==
X-Received: by 2002:a05:6870:8a0c:b0:259:877f:861d with SMTP id 586e51a60fabf-25c944b135bmr5603928fac.0.1718871385425;
        Thu, 20 Jun 2024 01:16:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:2105:b0:25a:6d0f:1a98 with SMTP id
 586e51a60fabf-25cb583ea96ls769459fac.0.-pod-prod-08-us; Thu, 20 Jun 2024
 01:16:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVEp2Jd3twLkWCDZ9eZg31IROhrs8FxcZy8H6HU1d4UJejHiSrOpFQm/iWiMwW2qtzA6hftrm2+7gfYB8a8X5CKQqhLwRRAwpMvSA==
X-Received: by 2002:a05:6870:e6d3:b0:254:a2c2:d3c1 with SMTP id 586e51a60fabf-25c949ce505mr5646669fac.2.1718871384621;
        Thu, 20 Jun 2024 01:16:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718871384; cv=none;
        d=google.com; s=arc-20160816;
        b=X4GcCGV2logiHQnv2BBX8bQPN+TkYy+cvrjGXkvGW7P4hwlCLkltRZp1Se1ITx21DY
         AnctcPOitwikI1w94AT82sMvYTruGvMDsOBTd4zFD3ynkVTrVwvWVPm0ChVDr67U8taP
         76xZwINgMqNL4FAq4jb27lNuhV92lS2NJSG1YgsZjL73CZy/3/6yi72kjvIK75D8KeNw
         ubrMbd+8sKD3m0Tm8nWTjW6QGLTr+Bwq+EeAVWYwS8O2kKZFYxslyO9P2bf57/hffIFm
         hrwVQbl0aDAmt45zOjZvPjUU1jENs0o2eSDB4grbekmp7AEAhLEc0wfspX2boikWR0hB
         8qnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dft9k4QwVExtZF9VSHXeFnA6FpkqOsI1kNGDVc3SntM=;
        fh=ZjaLlJT9k9SiqtIL537eaR3+P0JptNzfiAoIz/lixb0=;
        b=Aw3hRgZkIwqjMR7fX38mkx1w/Poj3mBD0WQAPeCnn0NWBB2UUjQgyoZI00XwbwE0yS
         69mfKKZYUrjoBAqciqXrnHPHJGquIHnfFUBouZGp6d/uVBZHjgVm1zWQ0Sgt4UjfL2sF
         p/0dZSa6uDrCjb4XDYi4y/d8X2m9f5J1SV3YIzwefQNTirRVUV4mrWy2bjoBbsvtdyxF
         TH364BERbP6bLD6ZVRTSD2sMlWpusCBO132GdCd1Bg5J/JPkA9SWrsVE3x//CWD2TlY5
         M1bjyNxhx22o3XbVC0u2ZoAKYUyV6W5MzwGZZb/JIbsV3own1FSGVIFrkLla9VTth1HT
         lybw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Op2ZrNsQ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72a.google.com (mail-qk1-x72a.google.com. [2607:f8b0:4864:20::72a])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-705ccbb1c94si622450b3a.5.2024.06.20.01.16.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Jun 2024 01:16:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as permitted sender) client-ip=2607:f8b0:4864:20::72a;
Received: by mail-qk1-x72a.google.com with SMTP id af79cd13be357-7971a9947e6so36334785a.3
        for <kasan-dev@googlegroups.com>; Thu, 20 Jun 2024 01:16:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUdtKAKl9v3DE8yNdEIObJwlQ7M9X+six+zV2exytXCIC+lSDlzY8PRrgZ1oEEU0vWq3fM75kIf4Tf9vDqzR2IkD3y5pAsUdrf2Hw==
X-Received: by 2002:a0c:ea85:0:b0:6b4:f980:9f2b with SMTP id
 6a1803df08f44-6b501e2487fmr52257526d6.15.1718871383512; Thu, 20 Jun 2024
 01:16:23 -0700 (PDT)
MIME-Version: 1.0
References: <20240619154530.163232-1-iii@linux.ibm.com> <20240619154530.163232-35-iii@linux.ibm.com>
In-Reply-To: <20240619154530.163232-35-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 20 Jun 2024 10:15:46 +0200
Message-ID: <CAG_fn=VfeugzYZ05O-XCo5GJA9m2S76VrwS7yc3uPYM6zUpKXQ@mail.gmail.com>
Subject: Re: [PATCH v5 34/37] s390/uaccess: Add the missing
 linux/instrumented.h #include
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Op2ZrNsQ;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72a as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Jun 19, 2024 at 5:45=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> uaccess.h uses instrument_get_user() and instrument_put_user(), which
> are defined in linux/instrumented.h. Currently we get this header from
> somewhere else by accident; prefer to be explicit about it and include
> it directly.
>
> Suggested-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVfeugzYZ05O-XCo5GJA9m2S76VrwS7yc3uPYM6zUpKXQ%40mail.gmai=
l.com.
