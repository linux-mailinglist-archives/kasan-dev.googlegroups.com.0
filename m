Return-Path: <kasan-dev+bncBCSL7B6LWYHBBMVIZGNQMGQEI3BAZXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 8ED1862830B
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 15:44:03 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id y7-20020a2e9787000000b0027728056580sf4010441lji.7
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Nov 2022 06:44:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668437043; cv=pass;
        d=google.com; s=arc-20160816;
        b=lDxYdV2fdTZsVkYWELroKfU/nHedaCqd90siKhFQoz93Cdorb9Fj9PFxGuSC6dK4XZ
         w0lCBtqhPdxymiXLcSjC8lxQjV4Oxnw4OPhS5W0n47kD9dFj3+sdDS90jMkQybG0K5r/
         fizAHsBXpP02Y6yoKCyCrZsniGvsDXkAoO3kyWi/KEpkgaREiE20AxGj5l5zxi2KQTDe
         IFLNish94QP81VSBhNifDKu1R2cupt9GM7XrErPDnDDIdwrGa7+SH5g3zfbrlB5GyArz
         fHQ3u3asAEbaQC273dSi9IR2o49ox4NgC63x13JO3GEqrItgRnjJWu3gcw6rW98TefMV
         LyrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=ZBcyZPtu4rVyrmxpRa672Z8aDGZXFMzyI4iJPCbbeJE=;
        b=SrDQefcz0TnhD04Rsk3aepvWuk9MegIVgWBxTwzyUHLwIA0NLra/AOS5dKpTiXNHlQ
         uIJ/UEpE3eGvzZzoUUzYMdcPO1q1249Do44nwzgk9gScMXdO4vOJN8IbkHdssLJILNUM
         H9FSnss31+7teCLfaGLCySpTwOggvv6filkAcRTP08RYO9arH6NTfjT+3zRnnZQMo73a
         mQSbI8tg52uceiwu4iJiKpBBUO2r2YZ0izrjeKlIo17XrB8xpBINE2VR79f1p/WDd8u3
         cCuX0WuQ7fJ91l17Sphf9e6kQh85HcjfPE2m8DauT3aYEw6GXdsrOlA8n1qGxBSehZqy
         3yeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ZHXettCa;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZBcyZPtu4rVyrmxpRa672Z8aDGZXFMzyI4iJPCbbeJE=;
        b=Zy5OyPPbmLnu5oN8eArBVJPX0fBRLewXVHbiI1yj4k2Bu4x2SW6Fhh+tUXXeJ022Hi
         j4bVVVWbUhdxJZBwv2rvFlpFIQRZ9/z8LT8AHPm806vDm98q5py4vrLvrwaodZLNPoZ7
         NqecUlxwEa7dayWVMltyAUSElAwPAY+FQat7hls/t6zUif66T129Lj09ehke37ifxG/s
         VC72XpxTHpJ8TFASmryeSgDpNVSL1aescluHJEHwCoa3N37Xs52kct8sbPbGd9DrjEHd
         Yt0cIOko6TaUELOM+Kdkbyld6adKAPNgCxhsDzgTM221bgCHNTzcBW/KSajDto12wELD
         39dw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ZBcyZPtu4rVyrmxpRa672Z8aDGZXFMzyI4iJPCbbeJE=;
        b=Fy76KoyJ7GuCmPGubO+eND3/MVrEazB8aD27yXUnyaG3Iivjpgx7UJUqg4v7E0usqj
         5ztH5U7/fpRvhCRizgA665rqYrX5ie/5vnKw8ifOJU/T4Lczc3O6yQULemEZz424mGqr
         CT8ZAFWEsbWLPL6BUl75LDm28jH7Maw6kcmo+/Gfl9amDP1kegypQBRS8gxexzNmOsgn
         dkpEOvru1XoQ1cMHirztJVjk57zeI6vl1xg2xQHlwDl/+mhvWKYogbtY0pVUwc9TGBs3
         0M4TyfFaXLnHlGCBQ8aa83E8o4pchxKoPTm15+2W2r6PmLSvBx2908nZyQ52ijENU6PQ
         8PAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZBcyZPtu4rVyrmxpRa672Z8aDGZXFMzyI4iJPCbbeJE=;
        b=f6K4hD7hFRkZQw7JsZk4jQ6I3KUoArFd0ysVs6DJDz9irJRLGrpIreTypV8/OeBEbU
         qnfQ9AbP9mOdxbv75lMF0EhjmJY1sCUad1XC1G5tMk2yoCgLsu5DffPB+MigzklGpNp9
         0ki1XZu9gpfUMa7YoQteQ+CprhPC64MvTDWKKROAJw1asThMj8I0qetX8kYj+BHsdFuY
         srr48HRuD+hxU/rkontisq+2y4Soj2/LXxfKLHP9nE8XdIY1MSDCscETi1r5+/rfmYOz
         wYNlPwkPyZ5dekRT1eNJ6dWpCUebo3APb5xrkRocVuz4kVOpkyU8DH96nryKm+Q8cGaK
         FONg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmJut6fAE92IWKOXyHuMn2018goMaE+8TyCdY+3SRmD+XcV6RUG
	/7CDX4RZBdj1anjY+a7enYs=
X-Google-Smtp-Source: AA0mqf4h6yOCx3ra3t4vxWw59WF2p9x7jcmuJ7Tygvi2A09LPE4/umMTbn15z8SBe6VaCr8xIKw4TQ==
X-Received: by 2002:a05:651c:130d:b0:26e:a:b5c9 with SMTP id u13-20020a05651c130d00b0026e000ab5c9mr4333434lja.481.1668437042730;
        Mon, 14 Nov 2022 06:44:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1022:b0:277:22e9:929f with SMTP id
 w2-20020a05651c102200b0027722e9929fls1768791ljm.5.-pod-prod-gmail; Mon, 14
 Nov 2022 06:44:01 -0800 (PST)
X-Received: by 2002:a2e:a885:0:b0:26d:f589:4120 with SMTP id m5-20020a2ea885000000b0026df5894120mr4674916ljq.206.1668437041298;
        Mon, 14 Nov 2022 06:44:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668437041; cv=none;
        d=google.com; s=arc-20160816;
        b=iUd5RvmubM+ZEev5z4ktkxDc2ZTjgIzjN4anEtXLhuMX5gBkE7RMvxMA1xRKY85L1Y
         V9tK/hH0n2qRA2TiUtpyPaGSY7zmuQcHsTkH+0TScFQdpkhrDgvbCl4V7t3N5g0T/D4h
         bYj2BvMJGnUo5NI6sq//tjQIcHThA73DDF3g1wfr4H0A9N4hbUwF9u2G66bKRojmT2eD
         bCGZC2MYzEhIOOq/bT3BtZvBlFXwQe597u85n7k8qw5Ls+1tQLpYY1fHiPOT9Yjxt2T4
         pxgzeaDAjsGVLeQm+8YfnBHLm7y7gvpajvTmAbirqqSpOBmZoEaKRbxX4vLk7BWgi4Rw
         8slw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=ejflZfRBJZNtbDrOFC8bunVAY8SzTkb6ZTYNd35CpN8=;
        b=kwsDmwPaOx097DQ8eqJvTbgkGt7uAB86HKHSvL8cWxnWdLM+SKynIEUZGDGYprf7BK
         fHWqiBH9J3rCp9WEgwTiMCSXGQcEDKLEngXc59UPDQbTfOPzvbFIYpVoKBO8FxKIyklO
         whD7xCfwgbc+VeF/p+8eTpNma+b8NbFrvG7TcCvXcIpa9OCCRT8CQ1AyN+TvF7srhoB0
         d+TryhhMFKkf3YlqgALUEeJQv84i6BbBB1LSNTYvRYmCgvIeyuFmaCXVMIiDRGdrgFfZ
         xrhXPEfmmzqRd1jsKlDepBxMrmIQNXK5ILcxz5PhexH/7oHZLX/UXo+Trqt5q8ScepvJ
         0cQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ZHXettCa;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x235.google.com (mail-lj1-x235.google.com. [2a00:1450:4864:20::235])
        by gmr-mx.google.com with ESMTPS id 2-20020a2eb942000000b0027724b9e43fsi365705ljs.8.2022.11.14.06.44.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Nov 2022 06:44:01 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::235 as permitted sender) client-ip=2a00:1450:4864:20::235;
Received: by mail-lj1-x235.google.com with SMTP id h12so13455485ljg.9
        for <kasan-dev@googlegroups.com>; Mon, 14 Nov 2022 06:44:01 -0800 (PST)
X-Received: by 2002:a05:651c:1a13:b0:277:113d:1c38 with SMTP id by19-20020a05651c1a1300b00277113d1c38mr4765556ljb.238.1668437040914;
        Mon, 14 Nov 2022 06:44:00 -0800 (PST)
Received: from ?IPV6:2a02:6b8:0:107:3e85:844d:5b1d:60a? ([2a02:6b8:0:107:3e85:844d:5b1d:60a])
        by smtp.gmail.com with ESMTPSA id u4-20020a05651c130400b0026e02eb613csm2053541lja.18.2022.11.14.06.43.59
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Nov 2022 06:44:00 -0800 (PST)
Message-ID: <3b7a841d-bbbd-6018-556f-d2414a5f02b2@gmail.com>
Date: Mon, 14 Nov 2022 17:44:00 +0300
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.4.2
Subject: Re: [PATCH v2 5/5] x86/kasan: Populate shadow for shared chunk of the
 CPU entry area
Content-Language: en-US
To: Sean Christopherson <seanjc@google.com>,
 Dave Hansen <dave.hansen@linux.intel.com>, Andy Lutomirski
 <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, x86@kernel.org
Cc: "H. Peter Anvin" <hpa@zytor.com>, Alexander Potapenko
 <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com,
 syzbot+ffb4f000dc2872c93f62@syzkaller.appspotmail.com,
 syzbot+8cdd16fd5a6c0565e227@syzkaller.appspotmail.com
References: <20221110203504.1985010-1-seanjc@google.com>
 <20221110203504.1985010-6-seanjc@google.com>
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20221110203504.1985010-6-seanjc@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=ZHXettCa;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::235
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
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



On 11/10/22 23:35, Sean Christopherson wrote:

>  
> +	/*
> +	 * Populate the shadow for the shared portion of the CPU entry area.
> +	 * Shadows for the per-CPU areas are mapped on-demand, as each CPU's
> +	 * area is randomly placed somewhere in the 512GiB range and mapping
> +	 * the entire 512GiB range is prohibitively expensive.
> +	 */
> +	kasan_populate_early_shadow((void *)shadow_cea_begin,
> +				    (void *)shadow_cea_per_cpu_begin);
> +

I know I suggested to use "early" here, but I just realized that this might be a problem.
This will actually map shadow page for the 8 pages (KASAN_SHADOW_SCALE_SHIFT) of the original memory.
In case there is some per-cpu entry area starting right at CPU_ENTRY_AREA_PER_CPU the shadow for it will
be covered with kasan_early_shadow_page instead of the usual one.

So we need to go back to your v1 PATCH, or alternatively we can round up CPU_ENTRY_AREA_PER_CPU
#define CPU_ENTRY_AREA_PER_CPU		(CPU_ENTRY_AREA_RO_IDT + PAGE_SIZE << KASAN_SHADOW_SCALE_SHIFT)

Such change will also require fixing up max_cea calculation in init_cea_offsets()


Going back kasan_populate_shadow() seems like safer and easier choice. The only disadvantage of it
that we might waste 1 page, which is not much compared to the KASAN memory overhead.



>  	kasan_populate_early_shadow((void *)shadow_cea_end,
>  			kasan_mem_to_shadow((void *)__START_KERNEL_map));
>  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3b7a841d-bbbd-6018-556f-d2414a5f02b2%40gmail.com.
