Return-Path: <kasan-dev+bncBC7OD3FKWUERB2HHVHFQMGQE3647B2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F5A7D379EC
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 18:22:51 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id 41be03b00d2f7-b6ce1b57b9csf1546015a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 09:22:51 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768584169; cv=pass;
        d=google.com; s=arc-20240605;
        b=aFU/7p9r5+xFvVqPhgn7gCPcQLvW7exfxu/YKShbE/mJLqZFH25ife5i2w2A5d9CAs
         09fWwn5UH1RsdtYBln7Gj3S9e+JFk7F7tNwjBXQAqDYGPQAHPEbufGvL/2l+xgi4bxBg
         yuTTjxeQJK6igl0ZuwWdCBktNBVRMXExlhcloch8CnNS3gzwOcnVNsG0hpCJcY5C8pQh
         TWOGcIl+gucUnq++pMRw7y1XQK1Bu7dSKpqZqORL3MxrIAYEWVQwZg9rEFdGeEomHwuK
         ynKwKlfTW3+edm2FpaDAND+dJzpIfQGwm+pGAY3Z2/wSQc9sT+EzpkH0JvspkUoANpDd
         T+qA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qkjRYaLP8HO98M9gt+yLiCnky3pJ6WJWDJwgansHsL4=;
        fh=LmQSkLhOJjgOKqin3sur75Te+TVDFguP0kb26LNWVIg=;
        b=ZTGdkv81nzCxWj4iH/xLlu99fUFkHjoCGflUN4TxnJwx9xcNy1L2FJAAtDiJlG6BFy
         Tqd2VKXvMuviaN0naGIH3nyHrleQymnd2UJy9hzLTNSGQ2LGq1f+34mR8hFg8cBCfyCO
         CcJLcuNcj3NvWhEWF+j2VjuWSsgiVRrpd3GPzAERZQ+ArwWpgy+hSS1aVbw0pmMl9xdd
         5M9xOwnbhN4hBKtOk+W3sdu1xwXdzoFQMO0s4rvgL6c3LkUfWybmZlzuBqsnOBIC44IL
         UXuK4jNKoj+Tq2WBk0rJeoStpxI1E5An9kESMz+geN4lU9zR6FEdhLkDVfE6kdqaWSdg
         eWFg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jmaisJrg;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768584169; x=1769188969; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qkjRYaLP8HO98M9gt+yLiCnky3pJ6WJWDJwgansHsL4=;
        b=tUNw9SRt8ALqIKeeesFKb8rhmJBQMSu7KNqQDCbHFELLgo5RX++B8l5RkslFZbNA3C
         HtoEymng9VlkWDod9blDxiPJLcOWsDBIJBLO5IGcq7iIvUEYoQMnCgWQvii8RKZoDMk8
         Bl8O/cl2Jx3ixKQY6a2ejBweBZoDpZV8IGJERR3I1tT96T6XWBrSLgUMPaDjsX6bgWfN
         TXmjVsil115pp+D2t79n0hNdFgmns7lbCT7aLImMobslExHEcdj41hfqXFO/D4K9kt6f
         QrsuTU7z9Sq0dZbD3po1HNHW18EMCzMzumggn91d/M8YyS3atdc6i5f+3PlwTX8+3syN
         mEIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768584169; x=1769188969;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=qkjRYaLP8HO98M9gt+yLiCnky3pJ6WJWDJwgansHsL4=;
        b=rkJnhk4Nlp+zcLp0rzc8WZJ/160dPHifWcxKGae3XZpdTDY7+OsRA+2UggMqV4riF+
         NAf4n+aP0Rt5T6XcTmnNKW47ucChyxVllx1l/GY7u63YDZBkUbMX5SgMJle/EO/Jpmik
         YiyipQBAfVJqXwFSccQGBr1+q/Mhd9zUa/I/s7LCUIah1HjrJRpth6urHOPfAFBN0m+/
         mUWGDkRHHSqx7YMD4X0prHBzoC/XXjiSBfCaYPUTtdBPSRCoUfrCLJEWFOkrTaZ28sZ5
         P8m6btFO9J1QGkbESp1cbdnzcybmkRqz9wEMA+KcZ9UltVlMjt8tPBk8dzUfRetO+TVr
         gIdw==
X-Forwarded-Encrypted: i=3; AJvYcCU4Vi8SUNGBCHXNIPdzvES7FvZ4RVt1xSYhc8hwe1Nblj6OmsmeZKkI5EX/EUeVhPEOcdbskA==@lfdr.de
X-Gm-Message-State: AOJu0Yx1J+1bcRMTpnXkG4Mnl2LTz2R7ZJWayUygAxqQ/qaExmqIb+WZ
	AX6Ri5OLfMhyOqAfcJJQAkJOrjteqcYDQWhhqWKWlbnfu5TzOp7YeWB2
X-Received: by 2002:a17:90b:3e4b:b0:340:bc27:97b8 with SMTP id 98e67ed59e1d1-3527317961dmr3008865a91.10.1768584169315;
        Fri, 16 Jan 2026 09:22:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EBtKR0kgJzAG3+JKEddkJJVFcXFINGr38maQLL2aGZ9g=="
Received: by 2002:a17:90a:ad96:b0:349:967e:1494 with SMTP id
 98e67ed59e1d1-352686d32dals2028315a91.1.-pod-prod-04-us; Fri, 16 Jan 2026
 09:22:48 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUDsVUIIWvH8Vq6+NcGBWci6iPrhzQDyQg23IHJeW24+sMce4aFQHB3w3GOgvpADAomQPY4pZY7Y6Q=@googlegroups.com
X-Received: by 2002:a17:90b:1b44:b0:32e:64ca:e84e with SMTP id 98e67ed59e1d1-3527317989cmr3211271a91.15.1768584167896;
        Fri, 16 Jan 2026 09:22:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768584167; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZlBr9ZrOsBX0uYKsU1EBixOOt44z4e0n8KU16IERFOrVS19lHbc4fCNLAPmry6OrWm
         KradnJNQI+8LVn9Jkqf0uI86H83Rl/aaKKvfXGod54Ldk0/SitUXsAZ9hha3TkoxNqds
         FoDWEkMgvNd4LMLcKt1QO1Ga0/mgGIpVTK+GHhQImksPoyWjSBiFG2zDJG2erkLvI8oG
         JkzpMnf1OHnarHLDFlbbTLQRPEhCzEYPp9ZKFMhSuwPiJv2ZkILjE0nPj0SEJOnwtY79
         XbC23erMbZV/J0bazUUpaWxNufcTj+e52i1QwRa6uaMfpYl3kFYLtG6QlotO5hufov07
         XrLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=o8bloAHXlRqX7bbyuExKq5up0OoLL7i4hXe/j4ALHlo=;
        fh=rmZ71EoDqAyB1z0iSN11hxpcO22NqsWIHkiCW1/Gy94=;
        b=bH1uCocp4MwWR4UQpLL7ixjeCW07XriLD7ilQPOSiK4ZMx1h8RKYsAxZQJB8qx1pOi
         syAikLI0a65KT1vPmTZx9Z9tgrUre3uB36n6eW+hmfKOrQ0H7CYOD32fV1BfbMBMhaXa
         fUnlImgF3T0m9wiCB4AKh9uVW2HDIdYxmgniLSBmVBasaRDq9NCDnh62rNZDN8YlD/5C
         AdH9WFBofvnkkaMoNhn2rsG7AyYoIH1cw/V4kUvPRIrMTeITI77msR1V16mXb/r94257
         Kj00Iuu8iuDe7NuWAc44U22udQvNngGtzj4P+4ASddPtcpKTNp+VnmiwiWQtUqsnHQYt
         7IpQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jmaisJrg;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x832.google.com (mail-qt1-x832.google.com. [2607:f8b0:4864:20::832])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-352741dfff1si17594a91.2.2026.01.16.09.22.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jan 2026 09:22:47 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::832 as permitted sender) client-ip=2607:f8b0:4864:20::832;
Received: by mail-qt1-x832.google.com with SMTP id d75a77b69052e-5014b5d8551so546841cf.0
        for <kasan-dev@googlegroups.com>; Fri, 16 Jan 2026 09:22:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768584167; cv=none;
        d=google.com; s=arc-20240605;
        b=lyNFSsprY9o3zA1NTmNrDvNdLXmZcrfV3a/uqUSoTXfP73j9NeDA1NXpWkp0xVcVR0
         t60bht7Q2l9w2u38Dcz7/LdGPHLRLwAdlRrXwGg4/TTP2r11RVU6VTF25R0x787PPFVh
         X2poxoZz3dXmVUENzb6Wxh1lzxzLh1BA+fBqtsJswalmCibJY53qNdopJqhXOzoeg8TG
         fCKBdLywo8KzfSn/EsjDfPq3lsDgfC97Z9i2N8ly4u/s1K4Zou/7kWpe5nNc90aKqg3C
         4q0lG/FixEw13YTMHOunUMlSfkX3XE7TvhkWGX16hZzbQGBI+nTHwbmtLg3Mj3/Udsh3
         AEbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=o8bloAHXlRqX7bbyuExKq5up0OoLL7i4hXe/j4ALHlo=;
        fh=rmZ71EoDqAyB1z0iSN11hxpcO22NqsWIHkiCW1/Gy94=;
        b=FQCkl7rIVsOCsizsZpZX40zhpkBzTEzy1BGcCJxDhas13QYYOKTxa1kkb+5mGuRCXH
         Q1dcew2yjoo9K/BcINtlLwTef0jqxkip01Rytxt3nAn7AFfUcFugAE1291jqiJhx6btd
         4eYNWcpm7CWzWHGpwBxRnmLoXncajMeWFpdSxwzzby7SgEbInMP0HB65KfzX12JK9o8z
         Zmx0FNNSGa5fPYJNpEiDcwmMmxwjTg7o507rreNZIrPJuEXR/9Grc9lh09b9vv5kkNAg
         fk/3mLuf8UP6EZnbZ/lwizgXNnPAcZ4yb8MrtxAPjVc2at6mIgfky91Hln3HurkqEXZG
         nEGA==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXk3tqtSPEWAb1hTfjcpuzU64PWEhRgH6ibYfm1tpdBO5ShK+fRc03EXT+yUC+61z26JlIe8vqnJQE=@googlegroups.com
X-Gm-Gg: AY/fxX70wWzQdV4ty0fhhKy8i2EdM1G0TBdGZTPHHNSx4h+9uWf5JsUlvR7uGtTURP2
	ILK2nyqDyM8NxjSn5AleViyZTykLJrudJytI5OwaSdA4Ai0kTqX2jMzLexju862XQQ21a+Ujy2W
	97tJGSQN14TPk8wuxIpc/NHrGj6mwXVQphi1KWyLzwlkf0EA570/LG5k3mUQY1/xDah5Kucq+I9
	/3yTlSmzFg3IpHctwwyf0YAblHjb1DSSzXDXi23yN8VyTB4ZrJu9jv//0SNZnV1k2Ld2Q==
X-Received: by 2002:a05:622a:1446:b0:4ed:a65c:88d0 with SMTP id
 d75a77b69052e-502a22d2091mr4481531cf.6.1768584166336; Fri, 16 Jan 2026
 09:22:46 -0800 (PST)
MIME-Version: 1.0
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz> <20260116-sheaves-for-all-v3-2-5595cb000772@suse.cz>
In-Reply-To: <20260116-sheaves-for-all-v3-2-5595cb000772@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Jan 2026 09:22:34 -0800
X-Gm-Features: AZwV_Qi0GmjrM2TkwQbQz0K1_wtQP23K0QN4VNJnjVMrHBscdtK49aOG8chDQLg
Message-ID: <CAJuCfpG0SCGf-TOTRi0d8e0Zoh4r5-xXByhnmJRSiyUt9=LO4w@mail.gmail.com>
Subject: Re: [PATCH v3 02/21] slab: add SLAB_CONSISTENCY_CHECKS to SLAB_NEVER_MERGE
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=jmaisJrg;       arc=pass
 (i=1);       spf=pass (google.com: domain of surenb@google.com designates
 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Fri, Jan 16, 2026 at 6:40=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> All the debug flags prevent merging, except SLAB_CONSISTENCY_CHECKS. This
> is suboptimal because this flag (like any debug flags) prevents the
> usage of any fastpaths, and thus affect performance of any aliased
> cache. Also the objects from an aliased cache than the one specified for
> debugging could also interfere with the debugging efforts.
>
> Fix this by adding the whole SLAB_DEBUG_FLAGS collection to
> SLAB_NEVER_MERGE instead of individual debug flags, so it now also
> includes SLAB_CONSISTENCY_CHECKS.
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Reviewed-by: Suren Baghdasaryan <surenb@google.com>

> ---
>  mm/slab_common.c | 5 ++---
>  1 file changed, 2 insertions(+), 3 deletions(-)
>
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index ee994ec7f251..e691ede0e6a8 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -45,9 +45,8 @@ struct kmem_cache *kmem_cache;
>  /*
>   * Set of flags that will prevent slab merging
>   */
> -#define SLAB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER =
| \
> -               SLAB_TRACE | SLAB_TYPESAFE_BY_RCU | SLAB_NOLEAKTRACE | \
> -               SLAB_FAILSLAB | SLAB_NO_MERGE)
> +#define SLAB_NEVER_MERGE (SLAB_DEBUG_FLAGS | SLAB_TYPESAFE_BY_RCU | \
> +               SLAB_NOLEAKTRACE | SLAB_FAILSLAB | SLAB_NO_MERGE)
>
>  #define SLAB_MERGE_SAME (SLAB_RECLAIM_ACCOUNT | SLAB_CACHE_DMA | \
>                          SLAB_CACHE_DMA32 | SLAB_ACCOUNT)
>
> --
> 2.52.0
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AJuCfpG0SCGf-TOTRi0d8e0Zoh4r5-xXByhnmJRSiyUt9%3DLO4w%40mail.gmail.com.
