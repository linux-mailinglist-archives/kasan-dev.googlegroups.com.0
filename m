Return-Path: <kasan-dev+bncBCMIZB7QWENRBF4PXSMAMGQEERN66NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id E826E5A76FF
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 09:02:47 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id u15-20020adfa18f000000b00226d4b62f10sf1572720wru.9
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 00:02:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661929367; cv=pass;
        d=google.com; s=arc-20160816;
        b=KVo+UInPhxhSXzsCoJ2nPwowwm4d1B5FsKw/qr/bHMCe1w7CQshmhlNJTY2fxKbts6
         q21u/2uYYTjiVW45NtjiuBHnZJ9VLRYm4afMPNyDre5hHWg/kElqiXsu0KUoXXF8AFZZ
         KPnHnE01xCGXpN3EaIrL9r+B2VasorAvYcH5ydOjnAYobSHcHFK5N1P4l+8reSqK/Ego
         F9GS4fmz8ZTNbRQaiOPOz05ygA7DQIa3f/3bJb2dqVXVbk6PYnRjpWG4EbZIliZ4HS6u
         kCWdz5TbaqcT6z3EQ9JgmHcBAnXv2b9xisk1oRItl95jqROhy0hwZoxpBYEIb60VshC6
         lDFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jX/biOynEb8pphOyp8T/XFwKWqDdC0vCwo5HKZMw1WU=;
        b=kWYrYBpf4EvjyFFpw+JRfbni6pHcZw0v9SdkW2NwnBky3H5hL1YonbzUaA218tfmyn
         otfw4chN4GpQ7/DoHSs/zeSv0gGAJ5R1VambF5Ezo0mvtHXx/VqfccZmwet/uJFxjJiP
         Cgx3KFYf7/rCaZ6YrIS+VH2f74dHvhKrSnqAiODe+hPBEFMA1gzCt4tX3g+zUfO0gREp
         PzDKQaWlGCbl5kY7Jd7lR9CgmrAgNwh2zfC68QO3oo2P1IHY1rAyZ2aPVNGKP40YlcAP
         VL2f1gqoof5cP6ezS2wq9idA6Veiusa57h5956TSjHBQhf8F9oroMtSVMj19OXAXpJnt
         TN+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QGl3n63X;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=jX/biOynEb8pphOyp8T/XFwKWqDdC0vCwo5HKZMw1WU=;
        b=aQUDuI/DEbH5j9T56Yndd4pwg2eyhFgp9WarnYdMM/a5sYQpD/oeZew9H10qRXTlPD
         3+9JjpAwxSSDBVgQQptyCsOrDLSw9ghev+Mwaf0MXpK8Mms0Zo2IDhsZ8x7wIemSwUqR
         Bs8wzW0kwyT0AvjY7yKBCT9MrpJOLdaS07eLP1YWK6rn9V9B+FVQvP9EXRRLSkhqO2Y6
         XeViv82T8osfzwPo3xnqu50wX9+ROllHJvT4HPHbYHXKjItiVqr+9BZqfvVPxYfCAMUW
         TB9p3gXvTc1NZ4oV2Py4CER3NuY0yZ5KXaa+vAU/bcLdX+1GbWnwXQ3itGRgeyHV7Exn
         HAjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=jX/biOynEb8pphOyp8T/XFwKWqDdC0vCwo5HKZMw1WU=;
        b=3s5TA1mvtXHrqdkSvF7IJW275fZl8b8FfCxHrm3q0N7fCesfHnLegH77JtV2OgfV76
         AK4bVDQ3RUcyCB7onylQelA8mtlj9UR/BP1KZDfDoGhh/tHjqgDdyenbgF/ojKr2w1fK
         c6vEY9/Ax0L7Rjd6J5c6XAneMHTfdjiK4qKS3guSaBt7987Z8GF4oIKR7poDg+aRGKQA
         xvSEMZSWuvloj0H6KATF57CdO2WIMuJVkkLxSSo1TV/Y7nsH3stddtTlIyMZs/dnURpo
         RMc6M4GdSfFpx2lJebSrUKs3oPjmHJTHrh0dp2iaXdj4EP/l8Sw7KbsqZT8TDrFXUivG
         mF5w==
X-Gm-Message-State: ACgBeo1/dQSZ7s3EnjGRYqXDqQWuapywlRKn1+unLorfHABhyNsYUjhR
	v4oB6VM3XcWFeG5bws12yzw=
X-Google-Smtp-Source: AA6agR5A2OtennfH282GSDuhpod/DyDw8HPy8xZZJY5flr8uDZsvZWMUbCj8nOdmKq8yFq5uOZkF9Q==
X-Received: by 2002:a05:6000:1a85:b0:225:721e:9c2e with SMTP id f5-20020a0560001a8500b00225721e9c2emr10966329wry.186.1661929367492;
        Wed, 31 Aug 2022 00:02:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1146:b0:225:6559:3374 with SMTP id
 d6-20020a056000114600b0022565593374ls9591975wrx.2.-pod-prod-gmail; Wed, 31
 Aug 2022 00:02:46 -0700 (PDT)
X-Received: by 2002:a5d:4d83:0:b0:226:d08d:35c8 with SMTP id b3-20020a5d4d83000000b00226d08d35c8mr11058448wru.4.1661929366431;
        Wed, 31 Aug 2022 00:02:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661929366; cv=none;
        d=google.com; s=arc-20160816;
        b=0dkxBFEtc9IGZtZSM+yutFCEKQPOd/e52a2Z8Qw2SBoMSwtd7qSCWLWerYWyfu7nWT
         AHiAnv/mgbU+CmfmbDrM0QjMoUeECDpxFiyTAZN6Bb/L+S6UV9n4QPcg3QE3ylyBKZ1a
         OR6ebe09PoxI790XMEjhKWY3ersd8asFcmbRc1cuxoFNlCGKpBOoSyC+0IJrHyFqnlY5
         yn96MXx1KDEw++rH6ZGCw91vgNJXc6zefX9Xj5SKLKDM64hbmCSHAeXZ7e92WlZbX7T2
         qSPF6GIiAsfXDFaEYuuLsgepEP6sAoL5EkE40eSBm0KtwoBPi8Yc9EAe5e1WIYJXdc3/
         WGPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rqfE2JeA08ikD6ycfm92X3Nv7MlH/Rvjj/XVSqLxbto=;
        b=OKASahDLAFBt8jRulfBXCjeDnUquK/XFHNyL/c8U/bkrfmKOsZBk+FN11MDCwex3ES
         r1vvcC4oMg8qYPmuK6Ld4uwLljveEpz8iGmGUcYDj278UtJogniiGCiBSZea26A7qYlc
         9uxXCRXF/jf1NpccSlhXdgRTuVNrkZgDEl52YsbWHB6TJGpJstOc//NJXGKcKftnp7+X
         6oWjywfmlnAR9XJV+4MnlAhxEja5xv56ke2H5XhFsz2+hfMrvwZmSeto4X3UW1A1u+9w
         rOERD/NIyj2t1o4gJbenbK2UB+u48Ac4jRMdT2JEiharr7gpn4h9xhAkUgzdLaxMuK3M
         oESw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QGl3n63X;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x235.google.com (mail-lj1-x235.google.com. [2a00:1450:4864:20::235])
        by gmr-mx.google.com with ESMTPS id q18-20020a05600000d200b0022560048d34si569774wrx.3.2022.08.31.00.02.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Aug 2022 00:02:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) client-ip=2a00:1450:4864:20::235;
Received: by mail-lj1-x235.google.com with SMTP id bx38so13617095ljb.10
        for <kasan-dev@googlegroups.com>; Wed, 31 Aug 2022 00:02:46 -0700 (PDT)
X-Received: by 2002:a05:651c:1146:b0:261:d36a:7ff8 with SMTP id
 h6-20020a05651c114600b00261d36a7ff8mr8371114ljo.363.1661929365692; Wed, 31
 Aug 2022 00:02:45 -0700 (PDT)
MIME-Version: 1.0
References: <DM6PR02MB6922BEFFD6AF46E62B57342987789@DM6PR02MB6922.namprd02.prod.outlook.com>
In-Reply-To: <DM6PR02MB6922BEFFD6AF46E62B57342987789@DM6PR02MB6922.namprd02.prod.outlook.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 Aug 2022 09:02:33 +0200
Message-ID: <CACT4Y+ZrpjxwVN52NJBeLaLPgTZC4_6wspwNJSe=s2NCdGTq3w@mail.gmail.com>
Subject: Re: Enable KASan for ARM32
To: Eric Sun <ericsun@qti.qualcomm.com>
Cc: Andrey Ryabinin <ryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=QGl3n63X;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, 31 Aug 2022 at 08:58, Eric Sun <ericsun@qti.qualcomm.com> wrote:
>
> Dear Sir
>
>
>
> I am a qualcomm BSP engineer , debugging kernel memory bug on ARM32 based DUTs
>
> And I noticed that there are patches submitted, is KASAN for arm32 ready now?
>
> Can you please share the patches to enable this feature?
>
>
>
> https://lwn.net/ml/linux-arm-kernel/search
>
>
>
>
>
> Thanks
>
> Eric Sun

+kasan-dev mailing list

Hi Eric,

I would start with these (+any patches that were sent in the series
with these patches):

$ git log --oneline --no-merges --grep kasan arch/arm
8fa7ea40bf569 ARM: 9203/1: kconfig: fix MODULE_PLTS for KASAN with KASAN_VMALLOC
565cbaad83d83 ARM: 9202/1: kasan: support CONFIG_KASAN_VMALLOC
9be4c88bb7924 ARM: 9191/1: arm/stacktrace, kasan: Silence KASAN
warnings in unwind_frame()
8b59b0a53c840 ARM: 9170/1: fix panic when kasan and kprobe are enabled
c6975d7cab5b9 arm64: Track no early_pgtable_alloc() for kmemleak
c2e6df3eaaf12 ARM: 9142/1: kasan: work around LPAE build warning
eaf6cc7165c9c ARM: 9134/1: remove duplicate memcpy() definition
df909df077077 ARM: 9132/1: Fix __get_user_check failure with ARM KASAN images
421015713b306 ARM: 9017/2: Enable KASan for ARM
5615f69bc2097 ARM: 9016/2: Initialize the mapping of KASan shadow memory
c12366ba441da ARM: 9015/2: Define the virtual space of KASan's shadow region
d6d51a96c7d63 ARM: 9014/2: Replace string mem* functions for KASan
d5d44e7e3507b ARM: 9013/2: Disable KASan instrumentation for some code

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZrpjxwVN52NJBeLaLPgTZC4_6wspwNJSe%3Ds2NCdGTq3w%40mail.gmail.com.
