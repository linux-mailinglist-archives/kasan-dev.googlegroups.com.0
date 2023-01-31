Return-Path: <kasan-dev+bncBDW2JDUY5AORBMOL4WPAMGQE5XH5PRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id EB6876835FA
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 20:02:10 +0100 (CET)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-507aac99fdfsf176529507b3.11
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 11:02:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675191729; cv=pass;
        d=google.com; s=arc-20160816;
        b=gPuRSt+cpV3Ha+i37UCEiUbJZAdfKqHvcRYOzGaSHlDOOF3pIVnEv6nDxCu1irDsYQ
         z0Kkx/5izyQjBpfzjJYOgRYHy/MPjmyO/gndWDAqajWaIOQQ8ghfS4DOrBO6EL3KiDHM
         FKn261FVRm+vqOeMCFnNvv3ok/o94iSiQ/NkmLwlFoJgOON76OmsYQz/3twKKQWotb8i
         OGcy45x4WF9Ze2VfdonopfreX6UGz/T05qroKF7vYJSASijOVCmzqbAGV98eWC8g2K7i
         mthU5qr3SQKgED0NGxW7Te88dm6PI0e78Y8A/0UcdZicfGSqZO183uO7s4oHiARkj4zf
         Wi2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=lDgxSBfoqiSzcmx2CC8ukbOfRX7oHfLtmBX5kTsUwZg=;
        b=Wy9R2NqIBQS5ZsDqj+X4FGQwO11XvwrXg0TA3jLqflzBEjDAP27F0PgbJ31JOrTfJw
         1hEH+I0eba3xINEci1MT04Dpyas1lvyeLMK8IWZsJOkkxYC180Y7aJF13GkHFBrDrp8X
         7MjtZ0pvz2xEf1PpsmPXOAsisBf6gk9HeMeHZC50ockfwyiAOh84KIxDQR5kaOa6p6PR
         2D8ecUJt1LGp3RIq/bidcMLhqCLi/YIxNAEOUOeYGe4597uukEYSOF9vkVpt5bqNDx8K
         AwzKnbDWZCNp8FkowKb/BJFT52YFhqQddYWyvqT6qHF6Zl9kONIRyrd6HlkuFW6YZADP
         Qteg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=YUleBjQD;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lDgxSBfoqiSzcmx2CC8ukbOfRX7oHfLtmBX5kTsUwZg=;
        b=rzp+FJ/WbkLNuBbULEbIdCjLHRxCHNOCgJ1CAvEjQjcDpAhH5/J7yd+q9X4NDzHG2R
         wWXR/mJn7UPOQ/bucW7glhWIRpLb95F3q5VyXFWGBkGq8OgPpZAwNd2MnyVXmtnjSqFl
         JSAIlKFfVVfbX0V8bxX+hmfheo9hVxMo0mwKR9TTeWgVSOUBmjcUGj94LBIpIxzKV43C
         80R3d1fqwMJeHH96pddJ6lOYzCEZ32Dn6twK+0Wfkv8E6nTSbA3w5rYdBRNt7s9w2/4U
         qBKKSWmc2zo1aQsHqkDPY8NGe03Ol2noQbLJoWwV/fvtK/KFTTW9v7mFknupsmnySJGZ
         O/PA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=lDgxSBfoqiSzcmx2CC8ukbOfRX7oHfLtmBX5kTsUwZg=;
        b=OoQRVTFfg2TdEx2DIIygIajYYJqbfHgbvnd+OovQGO6zRknh9gcKH8PJv/Vu3DQfmT
         p5aMCwEvhErEOkmmsBlYoUf4Vo19Wi4/TfizonJMhRYSfSrIvjCGstQaiwFn01MYQ6IN
         jL6pTJDWyO3HWY/FfAOLT5ACRkUjPjMF1t0csmJmirQd5rtXyUkvOYeLk1TKomftnk4u
         3FaxUtQVF9aJpHTmHO6hZcYI7OJhGtIql/jvrgp16nJhkxFt/JTQ09vpvYVD3luK8r/q
         Vh8qtwxWVbwVyOcCQD+z9GZoN93np4Nlis9xyxPit2uqis64WIp1iCZZ1gKdy4M04V3X
         984w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lDgxSBfoqiSzcmx2CC8ukbOfRX7oHfLtmBX5kTsUwZg=;
        b=RQ7Ys+KxVa0YE3D0opYMFFIlAyxdC0UZatsdNOnsnsHdp28k62udUQlc4xAyulrLUx
         Usy1a9f3CvhHo4K8rqhqJ9eRBXV+066z0nU03cKXqWXL3GXnR4Ej052Fwvj4lqmzUPuI
         E21DWoWI7ZG+0vWxCoILUfrkF2QmjSpcTyBmMMWvLCAobikXdwOjRxFYYb4v15nCv4Kq
         h8/l7c/phozO/P1sY57O7C6MV0F/L1xwUjpTgl1o0u7yuTkd3RY9fgQWCLTKbJR45kME
         csRCX/MRXNoo1QC4RLDjfZdnObAqGcVV4YE/GYZSfY21A18y85gJFje0PJOJoOpz2MtN
         W6LA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUHd991glWXvzhMtYJfS66blx8fIKaa91hoWMrDLtygINLBhEbG
	5XuLvkgA2IZIA4eTIrIPFzU=
X-Google-Smtp-Source: AK7set8awPK1g8yuTqmFIBoW25Cf5N03D9CD9EBzblY/y75Zs9mikPQlkgQNkNaHdCtdRLGn9Bca4w==
X-Received: by 2002:a81:144d:0:b0:50e:e7f6:f3d3 with SMTP id 74-20020a81144d000000b0050ee7f6f3d3mr1841565ywu.87.1675191729655;
        Tue, 31 Jan 2023 11:02:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:e084:0:b0:506:52c5:3798 with SMTP id j126-20020a0de084000000b0050652c53798ls10821354ywe.9.-pod-prod-gmail;
 Tue, 31 Jan 2023 11:02:09 -0800 (PST)
X-Received: by 2002:a05:7500:6d01:b0:f3:ac26:b81f with SMTP id kd1-20020a0575006d0100b000f3ac26b81fmr1531687gab.4.1675191728971;
        Tue, 31 Jan 2023 11:02:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675191728; cv=none;
        d=google.com; s=arc-20160816;
        b=DCCEwpjBsTKbyCQDn9FaZjNxaS9bzXzqEmwchZFPZzOfxcVFiv96vrlrqGw56CAn0v
         RgQc5kja2sE4csWq65BI3M7f/ygZYSglmpej8C0YGKOkhYE47RAOwFzeNoSfg8FWUfTp
         TCidEmbfNQgt4pW5O+6mna4HNTmuyNLUZoPkTIrQRq4eax6dHYaDbVycJ+YtGsrwmKmM
         8m1W9cgqHeqUmikoYfNsSLI0EjaxoMaR+kqfhNBIjDviPILkzsV8g/tZDWHMWjIrMY0M
         A6YwdzCa7qf1P23RS61IuVKOphzzaUQGIw41snQPwLVI7FSyBZ88BUaPSo+rVMbvREUP
         l74w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=njgLhJzeDdAc0gMdbdqYyGExvQqOhYrpiMsVMjpoO90=;
        b=AhyMQ8gbqAk6qBMrKsDssPoDhQWCJtcF0ze6p9rRNtkMQORc5JYgYEnFncQQZPdt4s
         CI/senlDGBlINjvvydizhYhB36UaoG0NMNzQX8NmxSU5RsS27T0K4UhkSDqv/+pszAnD
         fVtRKmHhUI0SH8lIqy7BBu2cI9Qaq/E6YSYDYI8tfOhyNMooXYg4OdXUp4d3cRaODEQ3
         LMr2+vzNWgINXcMYOmDZEDpPWU0/6uY01XSr6rAplQafiJmjEsmfECDHs5/WgGoOD95b
         kKgm89/+ULIUjHKSt1hHJEVGN5J8pQLIpfq9B1/SvnHQ5AzfnBvVPqHmPVsJzruWfob9
         o+fg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=YUleBjQD;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id bl9-20020a05613006c900b005e51a1a1ef1si1650644uab.2.2023.01.31.11.02.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 11:02:08 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id j20so4315480pfj.0
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 11:02:08 -0800 (PST)
X-Received: by 2002:a05:6a00:9aa:b0:593:e0ce:fc20 with SMTP id
 u42-20020a056a0009aa00b00593e0cefc20mr1063609pfg.28.1675191728068; Tue, 31
 Jan 2023 11:02:08 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <5456286e2c9f3cd5abf25ad2e7e60dc997c71f66.1675111415.git.andreyknvl@google.com>
 <CAG_fn=XhboCY1qz6A=vw3OpOv=u6x=QBq-yS5MmA0RbkD7vVJQ@mail.gmail.com>
In-Reply-To: <CAG_fn=XhboCY1qz6A=vw3OpOv=u6x=QBq-yS5MmA0RbkD7vVJQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 31 Jan 2023 20:01:57 +0100
Message-ID: <CA+fCnZfJdjgwoONLXcq4qdbMcJvRavhVp021XNM_7VM+4pUGyA@mail.gmail.com>
Subject: Re: [PATCH 09/18] lib/stackdepot: rename hash table constants and variables
To: Alexander Potapenko <glider@google.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=YUleBjQD;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::434
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

On Tue, Jan 31, 2023 at 12:34 PM Alexander Potapenko <glider@google.com> wrote:
>
> On Mon, Jan 30, 2023 at 9:50 PM <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Give more meaningful names to hash table-related constants and variables:
> >
> > 1. Rename STACK_HASH_SCALE to STACK_TABLE_SCALE to point out that it is
> >    related to scaling the hash table.
>
> It's only used twice, and in short lines, maybe make it
> STACK_HASH_TABLE_SCALE to point that out? :)

Sure, sounds good :)

> > 2. Rename STACK_HASH_ORDER_MIN/MAX to STACK_BUCKET_NUMBER_ORDER_MIN/MAX
> >    to point out that it is related to the number of hash table buckets.
>
> How about DEPOT_BUCKET_... or STACKDEPOT_BUCKET_...?
> (just bikeshedding, I don't have any strong preference).

This is what I had initially actually but then decided to keep the
prefix as STACK_ to match the stack_slabs and stack_table variables.

However, I can also rename those variables to depot_slabs and
depot_table. Do you think it makes sense?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfJdjgwoONLXcq4qdbMcJvRavhVp021XNM_7VM%2B4pUGyA%40mail.gmail.com.
