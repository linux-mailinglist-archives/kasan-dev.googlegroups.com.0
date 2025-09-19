Return-Path: <kasan-dev+bncBCCMH5WKTMGRB2PCWXDAMGQESFQSGMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 21C74B8A2C8
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 17:06:20 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id ca18e2360f4ac-88c3a3f745bsf517129239f.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 08:06:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758294378; cv=pass;
        d=google.com; s=arc-20240605;
        b=gEFq3/j2DShnvnQ/iMbzuJKCPrGaOBY2T3zdP4n+kOdqAIslQvUBN429XTHvaahFPB
         PrDg5b3Sk0s5BKXhuyTRZp4v8c5Ep04d6B4mDSwYKpUXWfJ1VPW7TDnL3N+ijEQoh6XG
         2rA1h+o0c3vIqLHjMxDRlE7qs31B6CBnIIiuKMXvwSFsb/tWh5SbRvOdVWp42Jg8IaH8
         oYQrZW7OTlBqrDNB3XRPNvTVC4ZFFppk1rRJE0YygRwk9xpuhHfYTPzcdJlnbT1/zIGl
         6YK3QGkb9xubjN+wHDrzPWmLemvS7vq35ECUOXElnGzTwXjm1aeZwOvlgnxfW2BDaqZW
         OhAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7ixBu1GNMCCpwjiTAMRtdi81gMQhsFG2Q44sN6W8ys8=;
        fh=glzFuhrhMXFiZkacX1P17e3svmcVGU9z+mlkZCH6v2E=;
        b=ZjDX7AKxOyYY23lFUg8owDJ0jIJjXt4KSO9MpoAyP6XvPrD89eJiRgJmSP8uh/0u/1
         sBf2o8JQYN1j7Au4IVDqCHFFP5TY2kydO1uBojIhTFIDtRJXfHsyuPUVvXhxZvL+Pr2V
         oG5lTZuac1Mw4a+P7125MILpi8h5cQupn/d0VVLj7oCICpi67sAyDREaUiu3ZCayrEpa
         IRCnrv3/rakgOjNoQSMvd9Bncsua1yAearWjXnKN5Tyl5e3P+LsjrTtS7ycSIQSgVhFT
         Ox8aY2qWRqmJHXnYFBfVd4L5UlZTLtIbxJh5fmFgyN9eq2eQurVmU2zxD7QCi9yDsgVb
         nlwA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vO0EImCZ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758294378; x=1758899178; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7ixBu1GNMCCpwjiTAMRtdi81gMQhsFG2Q44sN6W8ys8=;
        b=PFON2yfvjHwRgUY8DKT2Q7EQul/1/219xBNjpnZD8Ms6Z5fUgs2j0Uier1Dj+o3sUV
         Wh4OpzUJIhvBSAXVV9tILUOTy6Uyy/pCvxOYOkcXHBmK0DdkWIethbNx3VN5u235JBny
         BtF3TIf8kXNd/ZBLVngCCMY4io3+EHBAlUsbUs/muUU5AJeMOdF5dhgY6AE4kLvM9b1k
         9ncT63DpjukKczy5koICxYL6sp1YOMj27QNHIp0O08t6PwJa44eI4MqE1O/G7DWUS4/p
         E/c8etAv1XTP03erqKlpTDITxcvxITXQ4CX+k1/vMfEIaDhCUnQ7kQMvtR8nFz+HMGRp
         g+cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758294378; x=1758899178;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7ixBu1GNMCCpwjiTAMRtdi81gMQhsFG2Q44sN6W8ys8=;
        b=gA+p9eKDV7kf7dX0uwMrumn7etgObK+oBy9a8O1Zv3sCbbfT/rsdYnS54xuO0H9HQM
         Jr7sf13D3rZjcUeOKSgfUShGznCREjhsR4nnKCgTY+XgNU4nSdxE62H3Vlguxsrdgeja
         Sox8LVME25ikeCYf1sudUTWcBLknhHMGeIOEbD8QsuK69Jd4hw7SCVOf2MRtr3hnBwpm
         WQoGQRa05rleNNol2HH6a18Qv6zIYeU4tGZ/mLn8g7mjlWCuWwNzSkXspicGxLe+lhSH
         +I8qa8qbXOat6z+vp968+qBGgK9f9w+YcJkxnd17VKa31JpYgF7KZY6yh6rHuT9VdNzl
         bkHw==
X-Forwarded-Encrypted: i=2; AJvYcCWF64Xh9buifkl6ZLzlJsb/LDbT2O+9eOAtS9ZLatOPCoAtilXw4/PrJUV3gYqmaFpJau1T7g==@lfdr.de
X-Gm-Message-State: AOJu0YwHZ7seT+nED828XCpYmbKxX0TucwGJ+jndbJEWgzUrYbUqw6KY
	LmzZLMO3Vb3bqvDkLsc+n4DsQhc3087yJGFD+dfI/l8TGiVTegY6xWfF
X-Google-Smtp-Source: AGHT+IHHeDZIL7PlkJ7BptYRGWhuAa2Bi6HEDm4jTjntOlqJpXIOMIsjoW+ON3dS8ZUgQK4sHFpMLA==
X-Received: by 2002:a05:6e02:330c:b0:424:871c:ee15 with SMTP id e9e14a558f8ab-424871cee51mr27846715ab.29.1758294377939;
        Fri, 19 Sep 2025 08:06:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6u4wRSkUKHSWZsf9vQJRVxjv9OOa455cPFAbpIJYIcxQ==
Received: by 2002:a05:6e02:1084:b0:401:284e:ff00 with SMTP id
 e9e14a558f8ab-4244da39becls23763855ab.2.-pod-prod-05-us; Fri, 19 Sep 2025
 08:06:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVvYOvXjVGfp97nOS4G2dKA0UVBnciL3TzXfiEhthBeD9ObbBts/mSZXUgyqFcB/q+A3ClsrFv/+AM=@googlegroups.com
X-Received: by 2002:a05:6e02:1c24:b0:423:fb83:6958 with SMTP id e9e14a558f8ab-4248190b42bmr61802395ab.2.1758294371106;
        Fri, 19 Sep 2025 08:06:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758294371; cv=none;
        d=google.com; s=arc-20240605;
        b=CaUJtRLkMlhLPbW+Si9myMdz/ewqWgdy9mrXOpx9Eoyt+DPe9YC/Q4vvSqDhugTR0I
         M4VHuVZC9j5ZiNP3IAfRzgDj0OlFVrW3weuQpoUV5XL4jObZCiOJFdt46WGWus8YgchN
         xdVP8t0291n+iYlgdaTgKQ23C3Ob4q3gv/8idCItohRR/MI/zKbIGjW84F9EN+0nwod4
         /jlnnpWd/nta4NcCsLPShSHXPSYRHegL/LbAkpR80EwghXE/1m06Ek1KNHdHWjPbKXxX
         AN5xUCW1zjX5pREY198ZglVBliePuxmQNTE3PIKHjrTCM0seP1CU+AXo1UJ1enPQ+sTX
         UssA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=X2StnNKxKVl/rGS0fAgoxWZPalUwZSRkr2jKpUk0esc=;
        fh=wMSRCaVJBOo8YkrOR+M/G+BIGqjFuVqc3Xk3FWp1ytQ=;
        b=WvvjkjlmhiPX6U+czXoHmeqwzBDO3+knLCxy8SgyYq5hMujStGrlX0gBwvu8EXN98L
         TtkXRnMbIOWNCqJv3c7JnM4DZui01PBNVCVmAaEmIs7aqUY/MuvvRKviLrBZeNiiLmN9
         G7cAGNh638LbyQJUBHT3bAOuaGfJ5VqRV2JWQheqEQT5YUU2MdxTQknXniLniUPQ/xrm
         zE1Q1WafSFfCoZm6UulT2mD+NE9578+HsJB7yrCS0Erl+Lpgpft4n0R5yer9XocNeCXj
         Obq+xGW6zrfSmuvB3HCWzH7GPLLTwWDyUMy1XKyb/QQWTXWLI3y4hG7Zj64WTBDNuREN
         UKFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vO0EImCZ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2d.google.com (mail-qv1-xf2d.google.com. [2607:f8b0:4864:20::f2d])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-4244923f02fsi2350755ab.0.2025.09.19.08.06.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Sep 2025 08:06:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as permitted sender) client-ip=2607:f8b0:4864:20::f2d;
Received: by mail-qv1-xf2d.google.com with SMTP id 6a1803df08f44-796fe71deecso14802956d6.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Sep 2025 08:06:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUBkK+250YMRllLPKr51pHIFm4B6Hwzm1eu4DiRBSSegUQM96AtOh5CIpgv/D34nWI0wkZM6csqAAI=@googlegroups.com
X-Gm-Gg: ASbGnctFQ0gf2T/P97cCnvrPGXnGjlH/xASQGkF+OTPMeSLZDdwZTte6tJDVq04S8Mi
	U0wz8Z0Ny95uporv4BPIRGaIlOZ2szDJt6+IozYh2tV6xC91zB4DM3wFjB2hcY4DWamleZhzMp3
	6evG6pncZoOC00ee17U80tGdJBD7EsTC/ZfcZH1WY693D6Sjdg/NdBhsMjVj0R+hLRPkxFH1ZR1
	WEAoxXSw8xV4wYbFPdifZ0e1GTjNhv0U0z2hA==
X-Received: by 2002:a05:6214:2aa6:b0:787:68a5:51f4 with SMTP id
 6a1803df08f44-799139ccbe6mr37966906d6.26.1758294369549; Fri, 19 Sep 2025
 08:06:09 -0700 (PDT)
MIME-Version: 1.0
References: <20250919145750.3448393-1-ethan.w.s.graham@gmail.com> <20250919145750.3448393-4-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250919145750.3448393-4-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 19 Sep 2025 17:05:32 +0200
X-Gm-Features: AS18NWBlYb6i59Bt1eV3KacTLjZoCQjcTTUaAaIGM2IX6otsVz3ln6Zi77bGuIg
Message-ID: <CAG_fn=Xd07FvCp-tU_kSyjeJS-4gruaO1x5iowrQQ7zkv2cLeQ@mail.gmail.com>
Subject: Re: [PATCH v2 03/10] kfuzztest: implement core module and input processing
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, andreyknvl@gmail.com, andy@kernel.org, 
	brauner@kernel.org, brendan.higgins@linux.dev, davem@davemloft.net, 
	davidgow@google.com, dhowells@redhat.com, dvyukov@google.com, 
	elver@google.com, herbert@gondor.apana.org.au, ignat@cloudflare.com, 
	jack@suse.cz, jannh@google.com, johannes@sipsolutions.net, 
	kasan-dev@googlegroups.com, kees@kernel.org, kunit-dev@googlegroups.com, 
	linux-crypto@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, lukas@wunner.de, rmoar@google.com, shuah@kernel.org, 
	sj@kernel.org, tarasmadan@google.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=vO0EImCZ;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2d as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Sep 19, 2025 at 4:58=E2=80=AFPM Ethan Graham <ethan.w.s.graham@gmai=
l.com> wrote:
>
> From: Ethan Graham <ethangraham@google.com>
>
> Add the core runtime implementation for KFuzzTest. This includes the
> module initialization, and the logic for receiving and processing
> user-provided inputs through debugfs.
>
> On module load, the framework discovers all test targets by iterating
> over the .kfuzztest_target section, creating a corresponding debugfs
> directory with a write-only 'input' file for each of them.
>
> Writing to an 'input' file triggers the main fuzzing sequence:
> 1. The serialized input is copied from userspace into a kernel buffer.
> 2. The buffer is parsed to validate the region array and relocation
>    table.
> 3. Pointers are patched based on the relocation entries, and in KASAN
>    builds the inter-region padding is poisoned.
> 4. The resulting struct is passed to the user-defined test logic.
>
> Signed-off-by: Ethan Graham <ethangraham@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DXd07FvCp-tU_kSyjeJS-4gruaO1x5iowrQQ7zkv2cLeQ%40mail.gmail.com.
