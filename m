Return-Path: <kasan-dev+bncBC5NR65V5ACBBXVVYCYAMGQEJ3XEREA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BFAE89A170
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Apr 2024 17:38:08 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-3418412a734sf1478580f8f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Apr 2024 08:38:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712331488; cv=pass;
        d=google.com; s=arc-20160816;
        b=tluSSiTdDpOzJ3MDrDEEvI3IzrFl/V7mEXCdpVzicDvG4zXXBn3JTk+IUeELFk35UW
         jU1LJXWuekSQduXH8dU7kEwqY3aDof7tWVRf/3/xNmxiXQFvyoz58aGsWPIU5N/cXHos
         QtCBURVoVp0Php4WKSV8HY9NIUi7gN7DcetnAPP2Yv7nB8sLeAGWfAgOh0izeVLUKMVV
         OLnSXEsXijttO1loozXF3804viRErkqrsotMpRQktTVSeYMcFeEwwWkRk/I/3pm3d9mq
         ZE7gDrBfd6ZnjUrez7KKz2KIEShkR6Dw2DbAU42G9BIhakxUeQep7qd20MSABnKKlgQ4
         iu+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=qrzhYJJZ8diWRXs5quya+KuWbhVeCGkAEwhkIyBmNII=;
        fh=wpjKI72euGdbN4SRa/AEXFizv4UsmMlKbsvgC/pDOwk=;
        b=TXC3d093S2jeCOesKJWONb1CIlNgCjFE7ux8bWZ522cKemLfIDRfp3qsBEwje3T+Tu
         axfc1eDaabHNNjDuBOaHb9ARxMvGEEMF+qbmce1YbjCWB40w5zULkp4DPFVhv7nb3yG/
         fzS8oYZdfJmfjDKLxhdPNIuK12xibO/04j8xtfhLGcflTLc9vzTUuNt0kT68Ewf8fUMq
         I1H7CuZ72RHAsGa+4W+2TR2tbcXB3Xe92ijG0mMMtVE7yj0Q4wtmmp0o/ElqSByb4zRN
         gwx14lXcbzMVfmSVmd6TEwU5i4EMnTdXhaWIGo8nYzoFqNX5f3SajUJ7TphpVjekL2O1
         PeZw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AloH3duO;
       spf=pass (google.com: domain of klarasmodin@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=klarasmodin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712331488; x=1712936288; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qrzhYJJZ8diWRXs5quya+KuWbhVeCGkAEwhkIyBmNII=;
        b=jn83aiVpt5d2rofxAR4MjOaEXl81v3C71zMVhzG2grkjdCveSHkbQi+BH2pFqioujA
         f7VI708S7o8N3NUoE/14MhCiGNCY9Jpzi1wvqlJrNCkmpuFIt4k3rq89dDSKlFAzw/Iv
         xE9Ohzn9wNaQVN6mhPz7V+3AJEaHvoAKlZQd4UdyxUbJ2/dWYNkAs2q2W4JD0SSNfiJK
         Fs0oOixviSmQXztv/oOQbiMM00vZb58FEHtRGnrai8BZPZJn79iJMg+qjo3ZCbvFLkbe
         iLuq1kRsOrBK/x1urouXYwX6gz3d5hCfN9pR1i6S27Mv8QBQzl+c0xSxBYUP+pT3AqiE
         URig==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1712331488; x=1712936288; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=qrzhYJJZ8diWRXs5quya+KuWbhVeCGkAEwhkIyBmNII=;
        b=S3nT+RLrd8zSt751TSoBDeDmnhdtUfc9eHOLzrEbSeEshLunMK0Pj3mlZO4XgaFqzt
         BIZ5EOctC3Nb5GsWC9mcG1wCFvWglXmAcwrg5txRKROcjZU02M0Sy8slXOzl6OrXHDeO
         wlJKbr1ga4qzkldzVYq1N1kBNd5EFA9Quqy+BBVtFZIZNId8WY0uSPvzKA7jFL3TlfHv
         4RlB7CizRPaH5Exv7R5L41MM86GfEpKF+cU5QO/tXBXRrya/65v5QYSigCmkYPSzdNyb
         ED9vJ7G01Zy2jWheXRFTfQKPc5/+jQYstQiiVn8iWgUUc5NrWPVotB7CAqEOUtYHfNLe
         CBvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712331488; x=1712936288;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qrzhYJJZ8diWRXs5quya+KuWbhVeCGkAEwhkIyBmNII=;
        b=gaw11sYCjlbMn0CCe5VSQ9mq17V+KmpKP9cIem/AHzKhJaTylxqQ9hjgXihLNICstV
         4PvKkbfhnZusKppjJwlJpr3JGTx2UocCOCrPVopSAsy3fB+bDrCUaoc1k24NjVwEcgHw
         oK3KaGzwdlpBpRALD7ek4O5D/8pG5ogM6HkQ46TRtZ3rzeDbgwcFfwvJWVFQE8CyYOVB
         J6B0FBVp6UFEY0N7WCltYa0eI/o6wsgtLbj95CJTW7/ydCN1LTG38kU+6zuRHvBAF9KS
         YavD9sQi6Hvv9XrSIz3MmxaIB4ldJf6whnmRtjpabQtWLzqcK7ANjn1Asmgy5elrHojI
         /KIQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWHGT049vCRymRhS/LdU62Hrw8iWiIL1bZL2J3dC+9ifzl1aay+cslpALUfX/e7mAnN/mCQuDgR8qC3I+PemMa9ENt2OS2BZg==
X-Gm-Message-State: AOJu0YwB+TBBSGw8kNNt+7WG9t81UZ8LREqyzIfjLMb04fc8kIR217ls
	u99fe7oLdrkFGrRR8KUkIV/Qx2jFfnAjn8oskWd6MtYwEBSL4h5f
X-Google-Smtp-Source: AGHT+IGjkUU9kpTtQslHSDvexwiU0v5jS+V01YIZ+bPzcUHoHFHoqcB85ZFXXcGnlxNXXxnabOspDg==
X-Received: by 2002:adf:cd01:0:b0:341:c9d1:eae5 with SMTP id w1-20020adfcd01000000b00341c9d1eae5mr1310989wrm.27.1712331486859;
        Fri, 05 Apr 2024 08:38:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4571:0:b0:343:8a1b:61aa with SMTP id a17-20020a5d4571000000b003438a1b61aals821137wrc.1.-pod-prod-04-eu;
 Fri, 05 Apr 2024 08:38:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWy1L2VWTGeZogri0sZaGNGviJAo71T/9WzTWlijvPgpRaob8YVPet27w5QXqk7cbXJp2RaM1pyeZg1HkbuREpSRrgVbtkTf+Fy6Q==
X-Received: by 2002:a05:6000:d50:b0:33e:7a49:fe3b with SMTP id du16-20020a0560000d5000b0033e7a49fe3bmr1438285wrb.21.1712331484588;
        Fri, 05 Apr 2024 08:38:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712331484; cv=none;
        d=google.com; s=arc-20160816;
        b=nzzw+JOzRmq0TCvVC8xRFfI0CUk2GA3PbZjiKQZ6t0NlxU7XDhg5fph0UbstWXjtXM
         P/tDvQpwWjSAa9ytdI+E/TmvZTKQCkm4pZ+sbmAR0cbMsSNPdvVPI1bZ6eMh0KSb2r3J
         LtxXSBRfc4UJ1U7AGbqOoV+bzuuV5U1a1YxNJ6bw7XJXYzT6JMPDJJBu/y7x0RtcCHbD
         /rUmCPIovu+bugFhqgxuc6LUQgKCrUF4ZMrPkZEJJhBWINPk9RMyA44wOSx9UDuKDqpV
         pIqOjc4d381PwcZ54gUcwIlHL5fx3IVWParPjAKckzot8MHIUnbdlRMKd5G7JL1xrsu+
         Hlgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=A5HKjia/bBxV9bwJewCR86FUIvkQ6YbpSmsf0h/yiVw=;
        fh=nLnzSV7VKSQzjNu0YvvPlxvM7ylVqQ1Ob9MPSW8pqFE=;
        b=WfyVJj4VFUvyi2HJPumFA6Qi79gL+j4YO05cQX3XdhF8yQrYgTvKnGceDQumfR6LKx
         zWsPn5isrsKVUcl0PLrxqSKGqmnR+mMr3pBB1JX8gY4jhJutx4nXWNohYrXSSYqqOx2M
         cSP3R1nAZfwdp8NHispR93cmJ8yHDyoj583Ql76ZyoxRz25Om88ZrWXSyvWY+qh5OU9x
         YI7sU115mR48XwGlvH7NRluWhfN0V7fuDiUYOOFIb7KPublEcIKO0DjN2iLW1LnF/wSf
         9h+hsqczO/lKDeOgo+N98UttYWAQ4NXdAkpadRVF/8v5j5ZflLYlwPX9CPFaCqVrGBrF
         TnAA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AloH3duO;
       spf=pass (google.com: domain of klarasmodin@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=klarasmodin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x129.google.com (mail-lf1-x129.google.com. [2a00:1450:4864:20::129])
        by gmr-mx.google.com with ESMTPS id ci3-20020a5d5d83000000b003418013729esi68031wrb.5.2024.04.05.08.38.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Apr 2024 08:38:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of klarasmodin@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) client-ip=2a00:1450:4864:20::129;
Received: by mail-lf1-x129.google.com with SMTP id 2adb3069b0e04-516d487659bso993881e87.2
        for <kasan-dev@googlegroups.com>; Fri, 05 Apr 2024 08:38:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUn+T2KDHhCr7CURWudoBDgsj9343eY+GigfYgAGem3Qgt+6By6JSZrxu0DMXGSytxvFiyX3JSbNFo1Tax529aTgjeVm4tlQqOHOA==
X-Received: by 2002:a05:6512:2fa:b0:516:d029:b513 with SMTP id m26-20020a05651202fa00b00516d029b513mr1341784lfq.69.1712331483357;
        Fri, 05 Apr 2024 08:38:03 -0700 (PDT)
Received: from ?IPV6:2001:678:a5c:1202:2659:d6e4:5d55:b864? (soda.int.kasm.eu. [2001:678:a5c:1202:2659:d6e4:5d55:b864])
        by smtp.gmail.com with ESMTPSA id j11-20020a056512344b00b0051589cc26afsm218610lfr.72.2024.04.05.08.38.00
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Apr 2024 08:38:02 -0700 (PDT)
Message-ID: <3d496797-4173-43de-b597-af3668fd0eca@gmail.com>
Date: Fri, 5 Apr 2024 17:37:59 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v6 00/37] Memory allocation profiling
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
 vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
 mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
 liam.howlett@oracle.com, penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net,
 void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
 catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de,
 mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org,
 peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
 masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
 jhubbard@nvidia.com, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
 paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com,
 yuzhao@google.com, dhowells@redhat.com, hughd@google.com,
 andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com,
 vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
 ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
 rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
 vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, songmuchun@bytedance.com,
 jbaron@akamai.com, aliceryhl@google.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
References: <20240321163705.3067592-1-surenb@google.com>
 <c14cd89b-c879-4474-a800-d60fc29c1820@gmail.com>
 <CAJuCfpHEt2n6sA7m5zvc-F+z=3-twVEKfVGCa0+y62bT10b0Bw@mail.gmail.com>
 <41328d5a-3e41-4936-bcb7-c0a85e6ce332@gmail.com>
 <CAJuCfpERj52X8DB64b=6+9WLcnuEBkpjnfgYBgvPs0Rq7kxOkw@mail.gmail.com>
Content-Language: en-US, sv-SE
From: Klara Modin <klarasmodin@gmail.com>
In-Reply-To: <CAJuCfpERj52X8DB64b=6+9WLcnuEBkpjnfgYBgvPs0Rq7kxOkw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: klarasmodin@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=AloH3duO;       spf=pass
 (google.com: domain of klarasmodin@gmail.com designates 2a00:1450:4864:20::129
 as permitted sender) smtp.mailfrom=klarasmodin@gmail.com;       dmarc=pass
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



On 2024-04-05 17:20, Suren Baghdasaryan wrote:
> On Fri, Apr 5, 2024 at 7:30=E2=80=AFAM Klara Modin <klarasmodin@gmail.com=
> wrote:
>>
>> On 2024-04-05 16:14, Suren Baghdasaryan wrote:
>>> On Fri, Apr 5, 2024 at 6:37=E2=80=AFAM Klara Modin <klarasmodin@gmail.c=
om> wrote:
>>>> If I enable this, I consistently get percpu allocation failures. I can
>>>> occasionally reproduce it in qemu. I've attached the logs and my confi=
g,
>>>> please let me know if there's anything else that could be relevant.
>>>
>>> Thanks for the report!
>>> In debug_alloc_profiling.log I see:
>>>
>>> [    7.445127] percpu: limit reached, disable warning
>>>
>>> That's probably the reason. I'll take a closer look at the cause of
>>> that and how we can fix it.
>>
>> Thanks!
>=20
> In the build that produced debug_alloc_profiling.log I think we are
> consuming all the per-cpu memory reserved for the modules. Could you
> please try this change and see if that fixes the issue:
>=20
>   include/linux/percpu.h | 2 +-
>   1 file changed, 1 insertion(+), 1 deletion(-)
>=20
> diff --git a/include/linux/percpu.h b/include/linux/percpu.h
> index a790afba9386..03053de557cf 100644
> --- a/include/linux/percpu.h
> +++ b/include/linux/percpu.h
> @@ -17,7 +17,7 @@
>   /* enough to cover all DEFINE_PER_CPUs in modules */
>   #ifdef CONFIG_MODULES
>   #ifdef CONFIG_MEM_ALLOC_PROFILING
> -#define PERCPU_MODULE_RESERVE (8 << 12)
> +#define PERCPU_MODULE_RESERVE (8 << 13)
>   #else
>   #define PERCPU_MODULE_RESERVE (8 << 10)
>   #endif
>=20

Yeah, that patch fixes the issue for me.

Thanks,
Tested-by: Klara Modin

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/3d496797-4173-43de-b597-af3668fd0eca%40gmail.com.
