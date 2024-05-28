Return-Path: <kasan-dev+bncBCDO7L6ERQDRBDHY26ZAMGQEDED3YUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 45F1D8D20AC
	for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2024 17:45:18 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-529b632f34esf20472e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 28 May 2024 08:45:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716911117; cv=pass;
        d=google.com; s=arc-20160816;
        b=umFjwIwzmMiSuRJgG37/Kz3ycgUxcmJBMtmgwi3RMdfwvI0W4Y9u7jaDpKvMHe25GL
         ql3ukj9XCMmt3v7dJ2/OAiViX6bGIfzZOLiuwWhTuYouxN4uTlY0qmex33r/KWciqv0c
         nnOz+tpfTm+g0fUs60Llguum06S3sbLL/hquVSBjGWzDscYm+MNBkgNcSZ0f20Y3kAkf
         +Wr65DMb4+ZAUc+RZ7NINGKJzuuHWA3eVqIFqkMGvOoz9JU0iAoZwrx3RmRcLVhMh49K
         Lg6VqcoGBiDkaYtlhga5q8TUrrimlDmwvbZYQxYNNaOqMVNqfbeaxwu9JwpCU69cdHar
         J1XA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=vZKV3CzoGxEsXJEqDcuh4RTqV8uYm3L2y/uQbIDIgJM=;
        fh=XnoV+wC2MrvxfpsT15NwLC9wdsL0i8O11Q3FzXLIttA=;
        b=XqzmAwF8LzsLsXwoBRJCCVX67JBXHg/0QpEwFGuYEEiceNN3dtqgUjm+dJVXcXiy91
         u+ZQ/Age/PzBVkh9ljiarq20Tl6DvU4WYQMh6UDWtkhEg4hI6pS4ctfF+wtkgK7zj3/7
         5vdZaaN1gEHUMvq1SCIRZf+4UkxhZG+bjTZBbA36Dmt5ip6ppgQPCw/Zo455z9ig/5IJ
         zk3+cvOTkyjUAA7gr4PufgheGYd+aiK9CzPArvU/It1hvXi8/qy2sqprM3ng8BfgTMqT
         mp88rr2TDUlOS6cn2TkyTDwBkKkxadH4dkSG6OBi0f2bglanPimDDNJRqUaVoRdsT/Ow
         eGhw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=A2VdHbs8;
       spf=pass (google.com: domain of bjohannesmeyer@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=bjohannesmeyer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716911117; x=1717515917; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vZKV3CzoGxEsXJEqDcuh4RTqV8uYm3L2y/uQbIDIgJM=;
        b=O5deU+xAefg0/9xdk7YubAbqb/2RRBScXeNgiJ+SV4LMbjP36Q8Vgrqa6iGfqf5NMd
         4vWe/Va9BSOl3IRvLUuIjhTfmLpWz5xzcC1Zw/GZYDVRckyHYPriYonSXLWZURSoiIDC
         yluKfCYRYuwxTT+NyNR5Iru+hLdJnCJuyIlxHyPKTFYMaCqtA9r5yNydHG50cPhF67iR
         c2n32kOHHEC4dAEWhxb6HFowtDrcOTK5hCPPZ/D4p2a6V91CElZNKsJYps3QYQNm2T/D
         bwwE61iCa2AC35P5v6VKAPmJ41xRCbs68x+brozcZ/IIUMHYjEPjipt2MRadQ1Me4yhR
         jZCg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1716911117; x=1717515917; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=vZKV3CzoGxEsXJEqDcuh4RTqV8uYm3L2y/uQbIDIgJM=;
        b=UwOPrByZx/PLcC8D8uDs4KmRE+g7VB9AAdy6VV08RZQsaF/9dgMWtCdC8rzGM0WABZ
         YxB7GjlnWFVv+MdT+ZvIOtDy/pIjbLo1HQSQ4g6wjI+u2RI/fojYXTNZ+Zp0S1dM2jCN
         MluAzDO5B+7aF9sKVZ5aFUeXwckqvKZ35Raxcgo5jmfXzbopNrW8otmWfurVBjXhejNM
         O1hyX5X5QR30eVUyUDOpFXGJzuDsVWbtByhrErCk+CgG3j0qSFezlVqDi1xEmW7+EC+6
         JDonxmcvHjm+FZCKKyjTUgbU+WfL9RBo01yUVEf92Rx68XycMtUm9+kE01DINA71or5m
         3U2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716911117; x=1717515917;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vZKV3CzoGxEsXJEqDcuh4RTqV8uYm3L2y/uQbIDIgJM=;
        b=S/DViwlQWwIO/u7PJgAggIxv67Jj0zDx4Pux1v+T1bS+I6DnKpkTc6u0mGcFIRSLgE
         PU1UTWioiYD8/HfkkdfpN0mq7d2q1kwMMb/waOgI6T/grtXuoSTcfyTrhHJxK8dv/YFj
         38moYglXO9S7ggjQBT31P9LNLGhqIQSNQPK77GrHgFTNQXVe59OrZNQflD+ul3ndKO2i
         QwW9Om4NiLeDDkZJGsia+KQ+5CP2rPsL6pSUH9pIU4GKZVVs3nuvSTo2WKy7Rl0ldR5y
         R638QRsoilAhmk2tz2ampATMwLXlX3RpFq2NGk+BJAalM0VSxc9KbVdxQCHDehxAUgta
         Ejtw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUv90/5CBiT2uYNPKW4qwM4rfU7YyiEzziqBPuilelFQ91Tu0zrgmSW8BVnF+LogDlRDObqylUfC9ex/6YkyuiCkEkTK5n2pQ==
X-Gm-Message-State: AOJu0YzaciRda6CB4dROpf+lywv02r3Vb/JOx3+BiJHLUte8PjCJmWkt
	XrbJnqE1c1lCuhCqx5g8rTJQTYnaiqDVADQBxBvvhHkcqNCe05yk
X-Google-Smtp-Source: AGHT+IGHpGAubvIYT8HZUlHYwHKw5tGFbT58HrqGVRGekxM8cl6sQYL4PZFBZMaSLrY6Oxekp6hKnA==
X-Received: by 2002:a05:6512:b20:b0:529:a37:cea5 with SMTP id 2adb3069b0e04-529a5c938a8mr346621e87.1.1716911116967;
        Tue, 28 May 2024 08:45:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f10:b0:528:f700:bdd1 with SMTP id
 2adb3069b0e04-52937911d5als233899e87.1.-pod-prod-00-eu; Tue, 28 May 2024
 08:45:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXboe9VJuC5WL0vprnBcuYJ9GH7/qHjzBm7xDHtFJxyeA4ErvtSUYcRd/SHcqtWy9PtvWx2n17pRAPZNeFYYjTYiPLMe3K2ycSfVg==
X-Received: by 2002:a05:6512:3e21:b0:51f:458e:1bb5 with SMTP id 2adb3069b0e04-5294657830emr5277496e87.24.1716911114963;
        Tue, 28 May 2024 08:45:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716911114; cv=none;
        d=google.com; s=arc-20160816;
        b=u0htv6m/7Oo2fJsbW7zHtG+RyaDD0veSyU36XWL4YjJtbRx0zZxzDoza1Uo6gqL54k
         UDHjEWO3ieRlpsk+cNrKEkkFvH+FJInedQCjCS/Hz9sGtgCd8fOhvFqXl0W7+O5jcSkY
         gXAMGKCseoh/4YGUv9UuBYVv9c456AaXRd5Lay/TGrVoIaZK7F4UfE4zS+S7eyMI1wC8
         5JSSS15aBPJZBS3m75yj9BwCdvIqduDe1zrQZx9NOk3llRK992kZgehUx8SSWQX3nF7E
         ijrsJFf704GxJoEHHhsXE8dcvuG1jmKQIqJetQgfBZ40mwLlHpYkPfzU9z6lZbXEj0o8
         RxwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=BAqdiD54TVKMF2ArvdIVU/2qSdxUZTE4NpBmi7flC5k=;
        fh=RtBuNfL7oLnaht/JncNiYH8T1sllIe8H24K/UH+TARE=;
        b=R0fr49+CRFdCUqfGpx4w3FrhMpTMvpuctIg7F7MK8mOCV6RO6DQIuUNB+uwS+XV6S8
         IFTDYt04Hw0XiBWmkJhpN1R3sEnmFPGiSEC8GsgwyuotGLeNnIWtHBx8blFbqwqWSOSG
         PsPFv18KN6HtVeFQinBDtAFiLE878D0tKg6lBnpq27NkRh6n04qCZH0FrgWBuZB4B2OS
         +KdlEol1DrC8A4w7VRJmUkZVmU+fcZ6C9Rftgz8JF3zJ1jXjbfMdRC1zR8NqJL5Y7scz
         4k7wiqYJa+tqWVZPWVqc/hQDMDvXWo972K8Drz/9yueCa914k9bE/upLx25M5ebltRBh
         pVTg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=A2VdHbs8;
       spf=pass (google.com: domain of bjohannesmeyer@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=bjohannesmeyer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x531.google.com (mail-ed1-x531.google.com. [2a00:1450:4864:20::531])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-529b0ae64e5si91558e87.6.2024.05.28.08.45.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 May 2024 08:45:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of bjohannesmeyer@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) client-ip=2a00:1450:4864:20::531;
Received: by mail-ed1-x531.google.com with SMTP id 4fb4d7f45d1cf-579cd80450fso3981514a12.0
        for <kasan-dev@googlegroups.com>; Tue, 28 May 2024 08:45:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUIPukcuGnOJj8jK/3Bb7kCcewQfhOXeFSzLhmfL7Vby+Z3R7K53YTwNMinud1j3OsmlrMLVun62gSHSgV/Hip+5aiBSiftRLAQfg==
X-Received: by 2002:a17:906:b20a:b0:a59:c9f3:837d with SMTP id a640c23a62f3a-a623e9d5525mr1194850066b.30.1716911114010;
        Tue, 28 May 2024 08:45:14 -0700 (PDT)
Received: from rex (lab-4.lab.cs.vu.nl. [192.33.36.4])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-a626cc8e585sm621718666b.184.2024.05.28.08.45.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 May 2024 08:45:13 -0700 (PDT)
Date: Tue, 28 May 2024 17:45:12 +0200
From: Brian Johannesmeyer <bjohannesmeyer@gmail.com>
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kmsan: introduce test_unpoison_memory()
Message-ID: <ZlX8CLwwtv5ry7FZ@rex>
References: <20240524232804.1984355-1-bjohannesmeyer@gmail.com>
 <CAG_fn=U2U5j8VxrkKGHEOdbpheVXM08ExFwkqNhz4qv2EtTjWg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=U2U5j8VxrkKGHEOdbpheVXM08ExFwkqNhz4qv2EtTjWg@mail.gmail.com>
X-Original-Sender: bjohannesmeyer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=A2VdHbs8;       spf=pass
 (google.com: domain of bjohannesmeyer@gmail.com designates
 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=bjohannesmeyer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, May 28, 2024 at 12:20:15PM +0200, Alexander Potapenko wrote:
> You are right with your analysis.
> KMSAN stores a single origin for every aligned four-byte granule of
> memory, so we lose some information when more than one uninitialized
> value is combined in that granule.
> When writing an uninitialized value to memory, a viable strategy is to
> always update the origin. But if we partially initialize the granule
> with a store, it is better to preserve that granule's origin to
> prevent false negatives, so we need to check the resulting shadow slot
> before updating the origin.
> This is what the compiler instrumentation does, so
> kmsan_internal_set_shadow_origin() should behave in the same way.
> I found a similar bug in kmsan_internal_memmove_metadata() last year,
> but missed this one.

I appreciate the explanation. Makes sense.

> I am going to send a patch fixing this along with your test (with an
> updated description), if you don't object.

Yes, that's fine. Thank you.

-Brian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZlX8CLwwtv5ry7FZ%40rex.
