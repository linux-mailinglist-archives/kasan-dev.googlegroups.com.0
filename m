Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMVQY2ZQMGQEOHMMGGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id CFA7D90D48E
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 16:22:43 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-25bfed6a3f5sf72214fac.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 07:22:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718720562; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vddc55KriqUL3cDYjhtWPryqUwc5KMf73zCYHdVxm6JBHcrK0/7oBChHCAeZoRzvTz
         YLtUTdkv0vBSsH9x3EZLEATT3afNTf3Xeb4Vd7cZ2Im42n7DnTOgSy4CCDdBZeAa13/Y
         DJnDBa24wIm1FKxHPAb8WZp+WF9o/nAPuZLr7jHpFKY2PWBTE+WBRyB9nsThd5KhiR5R
         aXzKKrT4QtSMTcfKNxOdWotC7Ql3FD1JSxor7oBuUMJas1E2xe/OQ4m1r/5Lt2/psT9i
         aLlXf2D3BcBOgGol89pHO9pGkqvH9CtPKf34lEOpY0M8GqsUamiZzyFAZNJfFNyl+TQo
         J2rA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=W+JbWVbJxxfMhXvNUeSGf8MoqF8nX3+WKV3QEP9P6Tg=;
        fh=12vmBPYoJXmMGaec7AaNQoJmx4URCbbVfNTWccxxJIs=;
        b=p3wnt79jrljnhzhRUmNyvbV8PCX6CgJ3Oj4aS5CNuhZBwoWLHNI/0mkJ8dSFMCsecv
         r6pmc7tBuaRur7EW2IIeioV51hDk92LLioc7E24BowOqcdYN467aqZsZpWEBKYOIOurO
         v3r3uLqvAy8ImhzYdgPAorqDseEK0ZVdoyPYUeALn0HbZ/zkI6BpJIiISmxuEkAMDzQ0
         FTDHSV0v88vygFGRGF3R6iPe6nwCBugtYEt1hxSBIGYfRKN4oaVAFstqxkyx9s1mqHH0
         wgLqzil3RXdBA+1Mp1Z/Ee21tjf4r1oQz0HFPZbT/gGJIDp+Q57GhCwMjgyv8itV8qHy
         cJlQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WsbnbPSh;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718720562; x=1719325362; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=W+JbWVbJxxfMhXvNUeSGf8MoqF8nX3+WKV3QEP9P6Tg=;
        b=TRnMwxcIilXIM47lk187YHkLNYXNKlGPHtpdgH+XN5VZ+xOyEHkPQi6VBybFAMNIyt
         mmcfVHUF5aTWoNjWc5BfpsdgWgVfJaxkgGZ9/jHIAaTcqlR07YxP/+86wFp0naOZ1iZ3
         QsrLIVMN5CyZvGJR1d0FB6gTGN5ITQmkzwwMNp46voMHUaW1RqXGo4HjnMzjAO3FMO9k
         5w6RdnVRSNs3BBM07OFSPni+YD/O1TaBP0vikwsZEjjYPvZu/537t3+/n8WNXyXKKeXT
         rGsqCXRhEaYVs5Rscihox1VNeKt0eDeYbPJbXks3eJz6GRj0EYY9x2+Jhm5NTQwsSzRq
         ce1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718720562; x=1719325362;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=W+JbWVbJxxfMhXvNUeSGf8MoqF8nX3+WKV3QEP9P6Tg=;
        b=Jn9BO9EVsnlWypNZcjD3Ti+FVr/lgVKcNY/iCtF7A9pwLLCPxox6Oh9vFn/sZgIpJt
         m2CNq3qwR1Sa7AGQrFB6PXU/qUxQ06xEYnIYBBFiETXUqXr/Q6eDx6xMeCP6HHOi/NKu
         9BY3rHYCubTNk1EKkTY464reMrJOGds+Ygixl/3XoSmqcn5LkAq1D6sEyHWb+l9ir9/P
         OYefG3KkoUxjC6X8VVnN4CZTvsg+q60L1m7DIDSS34in5zYw08hrsjFdSVQS8+e01azX
         jOwaJV3OAkwCZpkEXtHauAQ/nZNpyw5kZNunIBVAQIp9D7j3HQ7FJWoEHTX/J3Mcvqog
         SNmw==
X-Forwarded-Encrypted: i=2; AJvYcCUV6AfR5VzyKINjEVyHkcwSxJ9agvqGjKx0ngT2bz46DJWxBlKahKgc77fcRLxky+5nwcNN0b8peo1Drzkv8JoY4e5Fd0rIZQ==
X-Gm-Message-State: AOJu0YyOf600VvtMeud8ACGXyU2xOQZl2xIT9t2kIjGwGCbaB0s2V6Xx
	nbAYWvx5G5+5TeYaegpls8tb+jZG2lcHbJjKJfR0au6gAPOSXjDn
X-Google-Smtp-Source: AGHT+IGolt0SI29idgF1f0DFRZCF1cmO+vPR41qFILqFQIGFzNUMhUJNWEje4UbSZWe8Zj2Ap2Ho4w==
X-Received: by 2002:a05:6870:d38e:b0:254:7ca2:745c with SMTP id 586e51a60fabf-25842853b10mr13567486fac.4.1718720562555;
        Tue, 18 Jun 2024 07:22:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:3a0f:b0:254:7592:be45 with SMTP id
 586e51a60fabf-2552bbebc2cls5460154fac.1.-pod-prod-04-us; Tue, 18 Jun 2024
 07:22:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWmSyJH6zIs6op+iIAqyZxsk5hsdzuDgwDeJEtay8WhVG8kIn5TiwXjTrNeNi6V8lAc1F0DY7/LVbPHY3LHF1iizJN2aRoaBxvK6Q==
X-Received: by 2002:a05:6808:1821:b0:3d2:4728:a05e with SMTP id 5614622812f47-3d24e9850f6mr14067639b6e.44.1718720561620;
        Tue, 18 Jun 2024 07:22:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718720561; cv=none;
        d=google.com; s=arc-20160816;
        b=KZRyln3uJ2R/7qfDd9VoOuQe4Yau0NTy0uEPveVGNUleFB5auuImOzGnJEe4etZz05
         yFkPGrl0HzzviSBEr+ublLK6pbZ5/dfB47KqXq6rEoA5IhwAZtM8SmyyKylQcVRre29s
         vhoKCH4bwH7acpy8Fug0+GMhexA8mncTBw2TcWM5dOuOLdXoiPgj6HgkWbmYyedF26AB
         WYh4zLQziEgG5J22aOBxyIuqelbJTGJQqiwL9zxeYSkfcm1h+jmP8soeepO9yCDR3p8T
         xxKogbTGEfQXn8hHP4j4hMBPa924VvlsRrtoq+EALyOH2UhetGrTMAZDowJJARI73bzZ
         F/Fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=U96e2ewUPGUwtDxZmjwxc3i6uzrFQ77Dn0ewyfhwgas=;
        fh=/kUFMIN8aYFVitgP2ls2/jukSS00bCp8VzTlbyTDLiQ=;
        b=kR2kM6atE8923NAjGja2x7237JecGpghlMf6KPnvoiy2oG72xVs5pG49lAYbPmas0o
         uueGlAb2XqAcjyE63aFbD1fLDXoaEnOJ2IA+je+9INhir7zSltbTTTJhdbXrhpF/W3Oz
         BntgGyp/rGc15sq/gZITzHQADVaAZc0DUHwiSDSGqUWpGOhe+l/pcPxQO79mmjCCxnK6
         Nelebohb17PbXIiFjNQyLK7aFiX/dyxreqsMKnfk//7Np09Hqv4SdQ21zduUtF/AWDDr
         /fQsdyttUp8W2H4CzfuxLLsmWhbd0h15+Nf2kFIWPOsRRLxW8jVr6NtgDDizZ1HOEgon
         4wKg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WsbnbPSh;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::730 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x730.google.com (mail-qk1-x730.google.com. [2607:f8b0:4864:20::730])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-80f4a1b4c14si97957241.0.2024.06.18.07.22.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Jun 2024 07:22:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::730 as permitted sender) client-ip=2607:f8b0:4864:20::730;
Received: by mail-qk1-x730.google.com with SMTP id af79cd13be357-79a3f1d007fso263869385a.1
        for <kasan-dev@googlegroups.com>; Tue, 18 Jun 2024 07:22:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUpoeW8ZRmOlUT5BUoCid8mTkCAi6r44DuBOXdkw6sgvqdSVf67Qes5UUTEYJS7hXcAU3TLQEStwyY/zUMoso5VZjyFsUkmtC4hqw==
X-Received: by 2002:a0c:f345:0:b0:6b0:7505:8846 with SMTP id
 6a1803df08f44-6b2afcf228amr120592576d6.39.1718720560961; Tue, 18 Jun 2024
 07:22:40 -0700 (PDT)
MIME-Version: 1.0
References: <20240613153924.961511-1-iii@linux.ibm.com> <20240613153924.961511-16-iii@linux.ibm.com>
In-Reply-To: <20240613153924.961511-16-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Jun 2024 16:21:59 +0200
Message-ID: <CAG_fn=WCNsF6HGALo0WN2POcyZ8ngmjpP9Wgqb9hXd4P9Z6geA@mail.gmail.com>
Subject: Re: [PATCH v4 15/35] mm: slub: Let KMSAN access metadata
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
 header.i=@google.com header.s=20230601 header.b=WsbnbPSh;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::730 as
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

On Thu, Jun 13, 2024 at 5:39=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> Building the kernel with CONFIG_SLUB_DEBUG and CONFIG_KMSAN causes
> KMSAN to complain about touching redzones in kfree().
>
> Fix by extending the existing KASAN-related metadata_access_enable()
> and metadata_access_disable() functions to KMSAN.
>
> Acked-by: Vlastimil Babka <vbabka@suse.cz>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWCNsF6HGALo0WN2POcyZ8ngmjpP9Wgqb9hXd4P9Z6geA%40mail.gmai=
l.com.
