Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBY7NYOPAMGQELHVY3TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0187167ADEE
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 10:31:17 +0100 (CET)
Received: by mail-qk1-x73e.google.com with SMTP id bk3-20020a05620a1a0300b007092ce2a17esf9196046qkb.22
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jan 2023 01:31:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674639076; cv=pass;
        d=google.com; s=arc-20160816;
        b=HDm0ZFwjiwhPO3OdgKsUJOD7Xz9Mp+wQ0ndmCkLU9bkLKN+OJGgI0hX1+f36W42oaC
         2wpgnMmJp1Q8i+g2FL5RiJ3N4LeU/be719IVz49vzTz8w9CIg97RMUO1ngKYIIJFnKKM
         IFUtPSyc5DDElQDqsAKGc88Kfze5oZniZFJvp4Lw1qxRaf1v2sL/gX4nVzjXh7zSyWnS
         2uKf1EQI7F5f4vDtIuuIzENhXS42LzDDtFAmfJBH+bwRCizAfWgMv9ruO4TzRpQyk1+W
         DKq5XpHfa+Hkfy8h7PS7GdiEBDM+V1OzVYhjsCL1nwgaytmmfwSACRfR/zEqv1uXDd50
         QT9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4IqgC0SLAdGQ6Rs7vYnFUWOUA39H83dXbVYEGKXGuws=;
        b=PeErPmftIYrFdczX+CCe9FZz00YH1vwzzIImOEADr3vfO08UG4fjIWSQgckZuwZYL8
         49ojOuwtrjV9QlvLvRWwiOI3L4f3q2305S0hCjNrVEuaqF5ALcxsPpiPm1MceKAAgTSh
         LGQonIL8EdZh8GRdyFUGTdiBaGkh2WxIPKTJjbfj6JRoFTFos2A7zgUQjgTkUop0qH9/
         QsYQiEXcbAOjow4hZ1X2c3egKDqVDYNr4f2jPPx1SDIcfxHb7ebgjIAHOD6CLSbbizXE
         279J9n30ZkFX1qlXJn/S87D3Bp4I7C/rSMK61hIn73OKJSTCJkt4Ar5gwCrKnJ1CXBvr
         FRNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nhxuEOig;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4IqgC0SLAdGQ6Rs7vYnFUWOUA39H83dXbVYEGKXGuws=;
        b=dXqyls595qrruQe/tlwBhNpwG9wgZPB6vFTB+cxHkugGRqG9HeEK9nsv/E9z7b/OB7
         1m/S/fxasLuq+axTunufPOxA5jjRokYiGob0oCMQMXy65m1TRHvIOkx8XuY6QuLHWVr0
         aydebCV8pXne/15ibgytmoVOM4jXANWDOig3oJZRlhwnxeOo6dEUq225xws3t73csLnX
         6ld5skyd6/c7Y8YjgJMWWrlIZdpCvfhGCE72r/Z3x2zTOFja84WyJ/DpgHWmc/BBZBzg
         sC61Ru2cw4RvFucH1XzSj2D75R2T8odmxzwxJAyWSBYcypNKs8lIUH1+ik75DVcqwjak
         Mi7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=4IqgC0SLAdGQ6Rs7vYnFUWOUA39H83dXbVYEGKXGuws=;
        b=jiJd5kVmaDA47kW/w6ZKldMSnCCSfTvuN/IwmoPvbiJoFYWrm11JdyHqDjkJl4otVM
         Q6IiDolgcxsUf4nkJMG9sEnc2H6uIgiv39i/OQwmAB3RIbqoiQ5uePyCKT7Wn70j+FHx
         2GvTLz6v4NNTHG0hhjrrID4IJ1ri22giXmW/9AKpfZyWStj+qmodDhqEmz9lsBqrU7OA
         J2xyZgSMgQc0uo0OwjaHpaK0lylxkz42VwpRGTkmQ1Ph2IYJQT4TM6ZwbRvsqHFyF6BQ
         7+STbQdoOSLLQ7ox2FBIunOXlpyo93lRtcfO0xI0F8ZZ25uPwIqcXvW9jkpy6H9jX2Uo
         tcxg==
X-Gm-Message-State: AFqh2krErmrijk0fO5E5gubZuq4pK1bqkqqip1IInke0Km9cz13Vi6uP
	z1o4BvV1Djs+R9SXqAvmoso=
X-Google-Smtp-Source: AMrXdXtqiQaUuLp17F0RjMy8jeTMiZmK7a4/lI674UZirGXrB4f1HwMYaONcmQQBGZGRHsgRJCsO/w==
X-Received: by 2002:a05:6214:3b12:b0:4c7:807e:d00d with SMTP id nm18-20020a0562143b1200b004c7807ed00dmr1614344qvb.78.1674639076002;
        Wed, 25 Jan 2023 01:31:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4991:0:b0:3a9:8ab2:1bab with SMTP id f17-20020ac84991000000b003a98ab21babls14161489qtq.5.-pod-prod-gmail;
 Wed, 25 Jan 2023 01:31:15 -0800 (PST)
X-Received: by 2002:ac8:5284:0:b0:3ab:b6cd:3758 with SMTP id s4-20020ac85284000000b003abb6cd3758mr46634128qtn.54.1674639075522;
        Wed, 25 Jan 2023 01:31:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674639075; cv=none;
        d=google.com; s=arc-20160816;
        b=S+nqHuDuQHK1KoY+f1vBgf6UlTXomWiugbH8p2xKsnTq9crsuEbZmEbZHAoZPw7dAp
         9qqXRVqDHQWbvZQSAXTSxnPkltRpVQVRibOXaqt+fMCYrGdHUfDVuKr4OJZstmYA9aV4
         FCTnQoMGJnz1Xu9yrPLdwjG6toymp9xolkeXeTF6FAPgrUJ+UdZ/KapRGmJefl6GJVwL
         OLDf7ECMTpSfvfL6jIuri174gGv+GQZWez7QIN+moi8wA/Y2EYyKg7/pi9DldudrRmlb
         Fa890vzmD6xiykQ6EXvqI+d2b0eW6W+GpnI5xKkrMiI5ozBiT9+sCQvGy+teqSt9ytvd
         qBjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=co74253xmdlMDYdyg36/gvO6JfXXpw4Mm4A134IXmAo=;
        b=Mlhccd80JPRwOTpmKv+u/9zAuZQ28cunieU/wVr8YnULg2SSFy4GfK8diTza83YATg
         qxgwicDzWkUgM3/4bNX+yVTeXZJflOO8w+rvNlh/7fIfYjM35po/Mgoi73iOVJe2ML23
         OCybxjKMPca60VtJgW1pZynuhi++uPbZzAPSFcwR5Gurs/FTJ4AqWwP19FetN8sPH/Eg
         SQU1cBgWxL4cPo/ZYfy2iiB5nuwIylFoFlpoDDN3TkqXLZIOLIOibMO62OMAxCZLdYD5
         pPQciwfGsdIUpvZdvZHjXC7Aah3wTJuBF184kGDB5KG06Zcqwt/Vw9OyPf98mlLGnVeB
         wFnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nhxuEOig;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2a.google.com (mail-io1-xd2a.google.com. [2607:f8b0:4864:20::d2a])
        by gmr-mx.google.com with ESMTPS id fg17-20020a05622a581100b003b62b73ff50si496188qtb.4.2023.01.25.01.31.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jan 2023 01:31:15 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) client-ip=2607:f8b0:4864:20::d2a;
Received: by mail-io1-xd2a.google.com with SMTP id b127so8221470iof.8
        for <kasan-dev@googlegroups.com>; Wed, 25 Jan 2023 01:31:15 -0800 (PST)
X-Received: by 2002:a02:2a4b:0:b0:38c:886a:219a with SMTP id
 w72-20020a022a4b000000b0038c886a219amr4163715jaw.133.1674639074852; Wed, 25
 Jan 2023 01:31:14 -0800 (PST)
MIME-Version: 1.0
References: <20230117163543.1049025-1-jannh@google.com> <CACT4Y+aQUeoWnWmbDG3O2_P75f=2u=VDRA1PjuTtbJsp5Xw2VA@mail.gmail.com>
 <CAG48ez32X1WKryh5ueQ0=Mn=PMKc6zunOYsMHhwMMMxKKaMfqA@mail.gmail.com>
In-Reply-To: <CAG48ez32X1WKryh5ueQ0=Mn=PMKc6zunOYsMHhwMMMxKKaMfqA@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 25 Jan 2023 10:30:38 +0100
Message-ID: <CAG48ez34j5HNfjT0ZAuehJm235_izkbYX2EETGSh402U7Hiisw@mail.gmail.com>
Subject: Re: [PATCH] fork, vmalloc: KASAN-poison backing pages of vmapped stacks
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	Uladzislau Rezki <urezki@gmail.com>, Christoph Hellwig <hch@infradead.org>, Andy Lutomirski <luto@kernel.org>, 
	linux-kernel@vger.kernel.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=nhxuEOig;       spf=pass
 (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::d2a as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Wed, Jan 25, 2023 at 10:27 AM Jann Horn <jannh@google.com> wrote:
> Oooh, actually, there is some CIFS code that does vmalloc_to_page()
> and talks about stack memory... I'll report that over on the other
> thread re CIFS weirdness.

Ah, no, nevermind. The corruptions were in ntfs3, not cifs...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez34j5HNfjT0ZAuehJm235_izkbYX2EETGSh402U7Hiisw%40mail.gmail.com.
