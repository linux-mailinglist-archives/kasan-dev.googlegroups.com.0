Return-Path: <kasan-dev+bncBDW2JDUY5AORBYG4ZSMQMGQEOVA2OTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1137.google.com (mail-yw1-x1137.google.com [IPv6:2607:f8b0:4864:20::1137])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BD845ECA87
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 19:09:55 +0200 (CEST)
Received: by mail-yw1-x1137.google.com with SMTP id 00721157ae682-3521c1a01b5sf18967207b3.23
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 10:09:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664298594; cv=pass;
        d=google.com; s=arc-20160816;
        b=uHUe521o6Y8n/oQraRlB0XnoM1fE9sskgG8EaktU6m6+O3UAAciDi7xvk7SPXex0+d
         eguDFSu/AN92H8qMX4YuKcp4GpfKZdiXOA0rCx9YMH4tcfFNERnqBqYdXcDuT0eaqMFt
         tcqtCU+06eFIeFFGaiFyobclOqYz0XDGbjldRsK8dx/4/FGGhZh1Td5mBjUQ5oKTVawG
         SfF+L5hRlB+/bWxT3uLExFcn0elfacBHT6r2O8CH65WkNJlTXAS5m7C8H3v9GL1rUUZR
         ls3rttgAaUlQ0IfpYkvS+/ihruwSJHq+y8LOvhJDgvuASKjxarSXi0ObLf8NYPiJY5Kl
         yLxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Db/Z1s9wncx63kYHHykEjPrwNWCCVK8hLCGCXAdY16c=;
        b=rFXGwuUUhwW1QJjFW0VqTrxjtb/2ouFFG4ElokyKbfoYLeuG1THMIfkcYYHunxz8F+
         M/DjAk3kes9F7k9sdt2hWs5I2aeJiLsMU51LI1nfN6YBol9XGQXocsaZX/3TiW7GzRF4
         lGMiYQonc/LIhZ0jSqG/9luNFGl0sMNyDb1GRpuAu5frQDGmjP8GIomVhnffjpuhmnYX
         ZOnWpFGiWnlOyjkLLS8ng4Q0SWSdfIbJI6b9lcbOcq2zPNXwDM5yKd+xntun0wbYVvAI
         QHF3FszU6XWXYeJrz3MRt4WkeKmiKZP/BdKK4wDkRSVZES3G29CXuektWcNe6PO49BuN
         bbjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dNquM4At;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=Db/Z1s9wncx63kYHHykEjPrwNWCCVK8hLCGCXAdY16c=;
        b=kSUqK3N10R6+k6JNzvcz1cjZekTgD9VoI59ouIT0AjjW3jsZ3e9joLk0YwUKmThFd6
         Z3kZIuzyB8oALbTgvumTSIoqICvf/B6bppRpyfraWeA39lp6RtGHMFBp5Y3e3CxhOIkn
         ORcAgpBTPzV1IGwpsw2fMmyukr9LCmW4dNAUsCnC6diFqa+JdMUgBGnS2SijgB+Vrw9u
         WNMhwbo3Im9vzybAwo94JiYViI/gkC+vZUK9QSgicP0+k8c42O+wjvjFWLlkiHsPUFA/
         SFRwUQ10yKHgLThLYyA7wvwkq7O3dv2Nqh+if1lzKJMF4XBT6CdCCAoYnY9hh1Z9uVeA
         KVJQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date;
        bh=Db/Z1s9wncx63kYHHykEjPrwNWCCVK8hLCGCXAdY16c=;
        b=LEnBQf7byhXFYmr6L5Dc+IpWNmNzgoHo0vrgAmF6u+QeebkdTb/IUKQiUGhhvZ4dTg
         cFtR01FgUeizHKteKgodb3HMamYLHJohD+Vn5zK84I/2LWUnWZNwULeodIyr3qkyL6HJ
         7eZ744uI2sLJ0uZBPfak0YlBGYKxhUEYP7GEJl6Tklc3lzK8O2QlFy7QyPEkE6uAeHM8
         fOk5yG/cIc1TXgSDT8lsax6XWggb3oIT+i0eJJ+7YSSCh4MhuAATRjJtpTHRnmjOnhRw
         ghEQohs0iVQUk7Y2twqGG9XKrKBuXOEuhzfrzFUFDVNWxEHMU3t7SrkWY07NMBSNSYxP
         or1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=Db/Z1s9wncx63kYHHykEjPrwNWCCVK8hLCGCXAdY16c=;
        b=wGM6kf4Gossp6TWT/0YzcGLrS6asC/Kj4b0QgIE6dUPIp/PPc5N+M/Q4fE7OCVl01O
         41GRJPR26C2XknqN6qxjRKgFwk7m7dq3LN4nBLHdpdN7bGQ4LC8H2rvA1WaXKu2C8eqT
         xSab36ny65UJAzLkaozp8OttwLMuYe9vrbE5pNW0u2Mg22yaVfRT8hm6/44pNclZm0Wr
         ZhMJMkiy+KM13bOaZu9/LUSAqHFS5sEtMGTukmXSr7sxFSuGue7lSMXIUgP9LWrK13X9
         DpJQ6+L7OtUrjaJzja6sxCvRgEHmGoTzEJYJcuOIzV3e4vKrF2+Sat37BIbqR+2rixTf
         Ol9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1qRgyY5IqgntzyXvYDTu5xPeJmR4YR7TZG1/9kTt4VyIY6o2It
	W82EX6xq5xrAg7o/LdUAXas=
X-Google-Smtp-Source: AMsMyM7KZxP5mdRq2X3NcXSF2Hq0c/E5uElrptwKX3vhYcj4yxhPbOxOs0R7BulY66J6AHXsFCsS8A==
X-Received: by 2002:a0d:d6c9:0:b0:351:b421:c3ec with SMTP id y192-20020a0dd6c9000000b00351b421c3ecmr4339663ywd.67.1664298592988;
        Tue, 27 Sep 2022 10:09:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:3:b0:33c:eda4:8ce0 with SMTP id bc3-20020a05690c000300b0033ceda48ce0ls1545516ywb.0.-pod-prod-gmail;
 Tue, 27 Sep 2022 10:09:51 -0700 (PDT)
X-Received: by 2002:a81:5717:0:b0:349:dd5a:52bf with SMTP id l23-20020a815717000000b00349dd5a52bfmr27666422ywb.410.1664298591570;
        Tue, 27 Sep 2022 10:09:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664298591; cv=none;
        d=google.com; s=arc-20160816;
        b=Lwo8mzmRXfftvgoTu8lsmS2u9oRsekvSRyV4de7CO15WaelhrMvkdr6IagYgw1hmyZ
         QKyz/MPBY7sUo7dlvSrzE6AP/8Zvb+lWDQBjxxLeZimQVCv6XjDU0tFqfVtgpxMmPius
         bhm7180PWHUzxAIlJjaPR7QDmKJ3XM3iBTm3Ihe4SNhuU8Oz0CZZvoAObXx9dFNXprDU
         drNxyInfO0vPeIW0V0YQkbMijWTcb2FlTl1arijf/6meGzDa9fXL5n95qYRrfp+tC+yj
         v8nFJ9hRYjUQAjYZa6KCsIjJJ9bAYeAc/BNCrCB6SIhPGQV35GjOhBxyxez9mqiRlkkr
         9dYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=v8DRSrWjsVtOzpUcdyfjM/wUO+MHVSat9Cgl6y+qF6k=;
        b=ijW2kA97KoQHqiTUqKCmNFxtPtBfi+IomNxRJfhbw5b6p4zoEH3NKJ0x1NR4TF+oB2
         kNbhXxjLO1A3jZJe5bP0wr+47Wz9C1mi5IfiTSxtkNa2zUa+9x1f1Zx1cN1S9SaGyq+4
         7eVgitCmus69Ye4lu9utns7rpSNTCABQrW+rCWIGN83PzB3AUTNh/CvlSoSlQlmDxdFH
         U5dLQEjJTK1GQIYi2SmqonAbzUnsjeWz54pi6bRo9L3cCJlRft3Jl+gQmpKYa36nc+eb
         JUFn85pYN0wz9EBuO9cQ3NDXxiuQdosYFJChnDWDal0V++TKeSD2BOF43yZqb68Wsj3w
         pJ1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dNquM4At;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x736.google.com (mail-qk1-x736.google.com. [2607:f8b0:4864:20::736])
        by gmr-mx.google.com with ESMTPS id 68-20020a250747000000b0069015ac7716si169284ybh.0.2022.09.27.10.09.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Sep 2022 10:09:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::736 as permitted sender) client-ip=2607:f8b0:4864:20::736;
Received: by mail-qk1-x736.google.com with SMTP id g2so6449729qkk.1
        for <kasan-dev@googlegroups.com>; Tue, 27 Sep 2022 10:09:51 -0700 (PDT)
X-Received: by 2002:a37:aac4:0:b0:6cb:d070:7842 with SMTP id
 t187-20020a37aac4000000b006cbd0707842mr18700315qke.386.1664298591243; Tue, 27
 Sep 2022 10:09:51 -0700 (PDT)
MIME-Version: 1.0
References: <653d43e9a6d9aad2ae148a941dab048cb8e765a8.1664044241.git.andreyknvl@google.com>
 <YzL29buAUPzOa9CG@elver.google.com>
In-Reply-To: <YzL29buAUPzOa9CG@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 27 Sep 2022 19:09:40 +0200
Message-ID: <CA+fCnZfus5WL9_-DQ8+jraQ79bE93VvGpd9iKRWcb6+rGv_mOQ@mail.gmail.com>
Subject: Re: [PATCH mm 1/3] kasan: switch kunit tests to console tracepoints
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=dNquM4At;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::736
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Sep 27, 2022 at 3:13 PM Marco Elver <elver@google.com> wrote:
>
> > -static struct kunit_resource resource;
> > -static struct kunit_kasan_status test_status;
>
> Also remove this struct from kasan.h?

Done in v2. Thank you, Marco!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfus5WL9_-DQ8%2BjraQ79bE93VvGpd9iKRWcb6%2BrGv_mOQ%40mail.gmail.com.
