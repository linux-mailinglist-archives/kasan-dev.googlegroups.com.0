Return-Path: <kasan-dev+bncBD6ZP2WSRIFRB4FRYGNAMGQEX4KAFLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 79BA66050FE
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 22:07:13 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id f14-20020a2e950e000000b0026fa4066f3csf7738188ljh.21
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Oct 2022 13:07:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666210033; cv=pass;
        d=google.com; s=arc-20160816;
        b=NZD1TGPqWuTfLRRd7a4yIhUKaeuqnkRXZgmIfuSGFAtL708fmEZA/MvwZh8DKINXQj
         4x/6m9ansvBllBz3wj5LRxNwvnGetPTCHqCVyTQqlqki0bPibGC49rhl/XEcpln3ow9H
         wsuqidUBAxfsGK95JZpB6+UIuKBQnnvjkFPnErpxxTjd3GFQ5aKBOybSp18Lb25s9M7g
         /1+WCKZcNpU0tlBO4lKg6KnxDqw4x3SoBQnqZk9NNvExkYwYMOl4aKfCSRghuiukPLaZ
         smL4mSMGngtjG9dOsV1OboCvkcdFMEzvwQAzHVShUJcr3qPx8RJeB2PokkkoYg8ajVEv
         FMjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:references:in-reply-to:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=a5EnZi6fZnkVgEg8WQU1YhKK4DJk1xaKBZ6sSdLjmgk=;
        b=g4AjdGDWWzIdfP0nxSU78at7/p8zwfbXsl1PcJLiwAxUl3hYR40YjRodZRMQUgBgV0
         5f38y4+GnJbXpsjVCPCDuoJKZJeKsgKxqWdNiTNbn3mYRSdKBncKeaksUpdHi0qOyrKu
         KcjKDfapWD/00loXAvu0TUiJUBIygpDxfmGc1mJeEqPbk8ly9RkXZMQYGwYQQSP94eLl
         CAFq1rpDedzQEIAJIBhMW+kTn6ClgNaxurmnocyiN4QBmc1MHQRjbJcSbECnlKpDocB/
         mi64NCdRDSSOu8n5cCzvEcgdlncFmdcdnRRamFEwD1v8IlZhLJYtewQloyYdQFbjIiSS
         lHnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=awEFpEhc;
       spf=pass (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=youling257@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:references:in-reply-to:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=a5EnZi6fZnkVgEg8WQU1YhKK4DJk1xaKBZ6sSdLjmgk=;
        b=RCp6AKr/CODgsLfgzIxwaViAmdmFv5v3nm0XECcBfOODCy37qSm/Bo2WYaw9p5eNn3
         Vex1OKDQe3kyarXlf3rD/FaYtzAazYVxb31Ld3ldOrd+BTvDT/YskJ5FD65xjPRxY2zc
         IQL2I7lNQL0HZari2CLowEbXC4tFVAjk6Fj4tm+f4zJ2IoG0JA/ePLk8ldvpy9uTJLoF
         1PbKfpspCGCv4bMknwJBJdSIkFCO2PM/wECL8LDsv09Fst5btKifIneDbTxB5z3ChbDO
         ozeJLthMIf7z3qD8FZjRaDyXrAb/q3hrvWI6nzAFss5aEHmjD73z99Rd7vJhENvw+S9m
         SgVw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:references:in-reply-to:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=a5EnZi6fZnkVgEg8WQU1YhKK4DJk1xaKBZ6sSdLjmgk=;
        b=JPyWwlJdIUV/7qZ0ynJyvFR1dulmROx00uP6ezhquP/q+kSoiGpXypMFYOO66tMP9L
         5JN8t6DI0fPZ51IfUJPbydCVznahqv6pjtv90w/zueqJCsa1GQunbSWxAyEaQVWtmPNL
         eopTuapal2buVoRYuAZRuOOhUBK8xWAcbz3qXDuyF1le/FNUjSNx3L5nePuhUpQcV3mX
         yxT/oqyfrnMpRe1UEoKFbCb0Cw0smSLYnPOulVp0gtKDxLYi+jqOC69F3nop55Iw1wSk
         P246kB5bfcHiNJhRCUXZ6krdnaa0ZFQDBqOmbqMc7U6bVHfkODoI0JbmhecnlS3YM9Rh
         FufA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :references:in-reply-to:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=a5EnZi6fZnkVgEg8WQU1YhKK4DJk1xaKBZ6sSdLjmgk=;
        b=1LiuTFS+u2CWMZ4pWodw++ogDnpAh/21Lta5MbusbQ6MRU3MxT2KkvgJpFZH+QZSe5
         ZJ2HmucU1XpFeQIG/SEIL/eRfcypQcaSFXgIk6MfMsB8BLwj/E2xlVPNPem+mmHzaSfS
         sSIFCZ4MstB62uS4p8yb6kosrOhSIHIEDzyqnD/OM9zCdI9Nps9vkmqdzOTWEuQKVv0x
         MYKcQSoIjfY+n9aolKoX+RD5v/Fpesb8b2nyMbB9suoadKySpGhqBPTbhBDCy1eT8Lrd
         PX5+Y81wjgpnIyFRm0uVdqxMKAmmcjOtRlhRwi/zAjW5sTu3sIMJxEPAZkoHK/YLCFw7
         pUqg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0cBhZz3dd4lmhWHJFqJfj/9l4GuB4kFTcGYF3Ob0cKfMI8vQ/Y
	PiEKGNuyWW4k12tL0zY2Tjc=
X-Google-Smtp-Source: AMsMyM5gatYUAuxiw0/BZo35dM+/NMHsTcaJgn9BF/tPi9B4zVOwkC3VJkcMT1RzQ5YTYbIiDLNy7Q==
X-Received: by 2002:a2e:7202:0:b0:26e:6f0:9f55 with SMTP id n2-20020a2e7202000000b0026e06f09f55mr3429628ljc.259.1666210032779;
        Wed, 19 Oct 2022 13:07:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9ad9:0:b0:26d:cef8:8887 with SMTP id p25-20020a2e9ad9000000b0026dcef88887ls3600925ljj.7.-pod-prod-gmail;
 Wed, 19 Oct 2022 13:07:11 -0700 (PDT)
X-Received: by 2002:a05:651c:98e:b0:26a:c93b:18dd with SMTP id b14-20020a05651c098e00b0026ac93b18ddmr3584597ljq.487.1666210031638;
        Wed, 19 Oct 2022 13:07:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666210031; cv=none;
        d=google.com; s=arc-20160816;
        b=VZdonCg8n6Ta/kXSdNVsxwlhq02DxmvBHV+hewqEkaveDp52mDNfvZSqa5irAXH06N
         jLWX+399uqeiZxqEwfzNVrbv0ykHmyPSEDgRB/8sxMhZbdX6ZtyhRfZlNUGQFMy65Oan
         8J0XvdtfJsX07j5cDQx1mf2kwR8dwCPk5jSf2g0ThxPTbP/h+iJfgM/rvLTj7N/ecQ7v
         d+uSxwqDaoqzHxr2P6aDA97oILtwIg4rV8hVmRnRkqd6ZAx6UdJ7R2zCX4gNCKh6Uw9w
         HnM5k9eiGzEeVUKyheMob+U7myXOxBFPABaieBnK5tAB8RrZhWGM0+M/fIhTKydji3wb
         bcKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :references:in-reply-to:mime-version:dkim-signature;
        bh=b7CNOQx77jxJkr8fo3A8KqRmFLYVGew+7knPtLNO80g=;
        b=FrZbY98tmJcGxBgZ/cpdju+0hju0qvjiG+Sn8DaCf913f+INCUPzD/eX2hfCOPgSVx
         oHpOr4agRg+DpFdjAtx31964Ts0pDKzN+QzOnyViYjWHPiT6R05v/W300IChWWDA6pIh
         L3QZP6mbf0brTpZ/8aNa6vNU0j/Rft5I3DYHhGD7nOv6Ez365dm8Ya59cs1MlEdnTeYh
         SLaVsq1DbPI7w5YTeMlBEYDbgDuQuluQVmMTU5X6Cl9YNe6FrHf2RISOJ7lmnmOTfWyu
         NFaiozrIuaiDNKWBMvXVX9HQ8nFXKjArqB0ZE1KrXbu2MU1rByKc8nOnF7zcTkcqXnIl
         snYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=awEFpEhc;
       spf=pass (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=youling257@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x233.google.com (mail-lj1-x233.google.com. [2a00:1450:4864:20::233])
        by gmr-mx.google.com with ESMTPS id k16-20020a0565123d9000b004a608a3d90asi55539lfv.6.2022.10.19.13.07.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Oct 2022 13:07:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) client-ip=2a00:1450:4864:20::233;
Received: by mail-lj1-x233.google.com with SMTP id i17so22634496lja.3
        for <kasan-dev@googlegroups.com>; Wed, 19 Oct 2022 13:07:11 -0700 (PDT)
X-Received: by 2002:a2e:2a03:0:b0:26d:ff37:f731 with SMTP id
 q3-20020a2e2a03000000b0026dff37f731mr3316534ljq.25.1666210031367; Wed, 19 Oct
 2022 13:07:11 -0700 (PDT)
MIME-Version: 1.0
Received: by 2002:ab3:5411:0:b0:1f6:575a:5fb7 with HTTP; Wed, 19 Oct 2022
 13:07:10 -0700 (PDT)
In-Reply-To: <Y1BXQlu+JOoJi6Yk@elver.google.com>
References: <20220915150417.722975-19-glider@google.com> <20221019173620.10167-1-youling257@gmail.com>
 <CAOzgRda_CToTVicwxx86E7YcuhDTcayJR=iQtWQ3jECLLhHzcg@mail.gmail.com>
 <CANpmjNMPKokoJVFr9==-0-+O1ypXmaZnQT3hs4Ys0Y4+o86OVA@mail.gmail.com>
 <CAOzgRdbbVWTWR0r4y8u5nLUeANA7bU-o5JxGCHQ3r7Ht+TCg1Q@mail.gmail.com> <Y1BXQlu+JOoJi6Yk@elver.google.com>
From: youling 257 <youling257@gmail.com>
Date: Thu, 20 Oct 2022 04:07:10 +0800
Message-ID: <CAOzgRdY6KSxDMRJ+q2BWHs4hRQc5y-PZ2NYG++-AMcUrO8YOgA@mail.gmail.com>
Subject: Re: [PATCH v7 18/43] instrumented.h: add KMSAN support
To: Marco Elver <elver@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: YOULING257@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=awEFpEhc;       spf=pass
 (google.com: domain of youling257@gmail.com designates 2a00:1450:4864:20::233
 as permitted sender) smtp.mailfrom=youling257@gmail.com;       dmarc=pass
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

That is i did,i already test, remove "u64 __tmp=E2=80=A6kmsan_unpoison_memo=
ry", no help.
i only remove kmsan_copy_to_user, fix my issue.

2022-10-20 4:00 GMT+08:00, Marco Elver <elver@google.com>:
> On Thu, Oct 20, 2022 at 03:29AM +0800, youling 257 wrote:
> [...]
>> > What arch?
>> > If x86, can you try to revert only the change to
>> > instrument_get_user()? (I wonder if the u64 conversion is causing
>> > issues.)
>> >
>> arch x86, this's my revert,
>> https://github.com/youling257/android-mainline/commit/401cbfa61cbfc20c87=
a5be8e2dda68ac5702389f
>> i tried different revert, have to remove kmsan_copy_to_user.
>
> There you reverted only instrument_put_user() - does it fix the issue?
>
> If not, can you try only something like this (only revert
> instrument_get_user()):
>
> diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
> index 501fa8486749..dbe3ec38d0e6 100644
> --- a/include/linux/instrumented.h
> +++ b/include/linux/instrumented.h
> @@ -167,9 +167,6 @@ instrument_copy_from_user_after(const void *to, const
> void __user *from,
>   */
>  #define instrument_get_user(to)				\
>  ({							\
> -	u64 __tmp =3D (u64)(to);				\
> -	kmsan_unpoison_memory(&__tmp, sizeof(__tmp));	\
> -	to =3D __tmp;					\
>  })
>
>
> Once we know which one of these is the issue, we can figure out a proper
> fix.
>
> Thanks,
>
> -- Marco
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAOzgRdY6KSxDMRJ%2Bq2BWHs4hRQc5y-PZ2NYG%2B%2B-AMcUrO8YOgA%40mail.=
gmail.com.
