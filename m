Return-Path: <kasan-dev+bncBCKJJ7XLVUBBB572264QMGQEEU2WUXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DDCA9C8BF5
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2024 14:39:06 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-5cbb635c3f3sf732711a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2024 05:39:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731591545; cv=pass;
        d=google.com; s=arc-20240605;
        b=WC2LNyADzy1oma1x9posCyKfLxcYEYqgirbDcIGnrmmezx2jPysnRHe6Jn8dhxk+Mw
         2gy94GdnikkC33Yys5tVlzNFkLOdHEjPMv+2g18W9JwGitZ6Gp7P9nHwhuqwHUY23akd
         UbzM/R4x/iP7FRgEKSWhTUgKcaUWLCXOAGB/U1XHTV04bysnJot8AGmNFL+OlL6oE70a
         91wPBp+7pj+OJLi0ljqJNRYvsaNhjogl5fpE9RVnYi/Slo7KWKyD3CsOFqGuhzZH8b32
         y7ZwuDXI3JnSZ/GhxlVZZZuNG14KmLMRdjUc1/uwbHXvKJo08C0szMrvpIPnj51ZP+1S
         wL/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=CsRH0ikP4mMBzDosDaPfSyrt/HW09mv/1ZJTCmxLdGA=;
        fh=oEHlXwd/uIUEaK9f/sV8fxWJIuldql+4z47m9fznPwQ=;
        b=E93w157FvXUxDveWBbczHZ40kbzUyrEDenosNXsxcaAAa0VxsiYjSwAiGP15tcwpdB
         zN40GZmf5TrrbT4XqRnb68KikWfSXMgZbLep5lxhARG7SIwGgLNE+G5692xOn73Umb2q
         Spgia4Dsw8TT4GaO7ci0a9PKjkksezOjP1em+pum3QtKPLDKZfc66nlMY+BHbnGMExGb
         meJXoWwC5LKqRtTwvPaLDvLFBdq1UzKX2HfQZVTR9DJ5K1a/cJtereNWq9Zy+jxJMzRU
         p5D2oxazwflR+PeVqmc8K1qLlt50PpOygQgBbV9ZHqkuyoKw3RzeaxXM0WuPuUThuWdz
         8GyA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HTeoc2xE;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731591545; x=1732196345; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CsRH0ikP4mMBzDosDaPfSyrt/HW09mv/1ZJTCmxLdGA=;
        b=gNdQxNSpxonPQr4s23Bd2iLo7E0jIr/Z4xP7fHHldn959Ang2LKqsvs8QPcOiIvZkA
         0FEDgv3h06L6MZTpFsu4sObQw87pCDtaCwNjXqmiWtFFUakS4X3b8V9Vx8CGXTsNHRzD
         tTtXlXHPVnbj1Gt3TSwVl8nYzGwn4yhMIVMQzk97P+su4KO9YifV/QEV8eaCEM14acu1
         bV6GSdRCnHhcnSAtMW2BIwbUTLw/vNiTI8k7irH9icygRdQoAO6vk2V8NeMGr2YVpCQH
         ymRVbds6+kgiNHkSOY4VQImwMBdQ5Zw6y5gsKHOeb3hhJDJcPJxHaoz11DHEmSwAcE3b
         XgrA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1731591545; x=1732196345; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CsRH0ikP4mMBzDosDaPfSyrt/HW09mv/1ZJTCmxLdGA=;
        b=bI348rS3hVWNS8Y1mTuPhebG6yheDKvKBPDvBUA9mlMRi/Vsb7w7eGuwH4o0WiBlM0
         Ap9d5K+SzD4+GXGlNV6C15xz0M9Fhfh9CH+xLpeNIzA8BZpxN6/qeEcC/CKG2RatVe2D
         tk+Oo8aa1D4awYhl8NQmiZGMOZtuuklZSLDTg655gQkfti9/EnLmEQBV0wcXw0uDFo2W
         mEr6z9tfoI5Is70MZShRPzEmofjoGUTfBKo8PzJNDCQZnxcvCwXEOtdajNG7gp8/iLAK
         H6So5GrqBTvCewq+JItRX86Nsn5F5Dsd6U0xF8i6cxUXZ5vbR9DwOWT64vgGENbpbkDi
         BLIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731591545; x=1732196345;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CsRH0ikP4mMBzDosDaPfSyrt/HW09mv/1ZJTCmxLdGA=;
        b=d8y8yPjOhNGEpCRRSu46JvwWK4AWvxOdTDkv5SC8GIqQ8WZLK/3cE27pjJH0+OCzZU
         58XphZODMfyhVFHyI4LYzOESxSFheVITGwEWGOVD+xXpl2Od1SEArxmmdZNdZIfFITFw
         BSsw7JhG4Po3jtdYSBvgJ+3NWIdaFKLScyVaQWQjBSlJ68cvqXqinSENkMeRve69V0IM
         9H2lTlpgiQgY+CzZfEioa1izPrQu1RvLewyeohN04rze4MTpvrJIp8dMa/BhK+JvPppa
         9NRl7sHrZJvGFQU3GWpEQ8+x3IOjgQ9nBvVwFoqLpryLjlHlH758yHYQ5lm59XGQ6equ
         37XA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWIT5+ljWGUaTrzryhsxREBICDuOqvZDV1VZdmZB2pEYa3ag2wSCAXHsDB/XS9XwYDVV6E7CA==@lfdr.de
X-Gm-Message-State: AOJu0YwLQBrC1z9Kpi72WN9aAx4dBXXCWylVc2G6wmdqEfq+RIA1kOBE
	/fG/YTrL25uatUYmoyaRRqyzqVPGOaMT8jsT7fLwNZN2RxI294U4
X-Google-Smtp-Source: AGHT+IGnXuGp6r/fOS7uplGqmLKaDOnqHOsUU5HkasILcY2H3OJjiVhbkhR1Kwk9HB74waM4VSh36A==
X-Received: by 2002:a05:6402:5193:b0:5cf:767d:c442 with SMTP id 4fb4d7f45d1cf-5cf767dce25mr2501849a12.13.1731591544321;
        Thu, 14 Nov 2024 05:39:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c713:0:b0:5ce:c9e0:aece with SMTP id 4fb4d7f45d1cf-5cf75811cc9ls229847a12.1.-pod-prod-00-eu;
 Thu, 14 Nov 2024 05:39:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV0m2NlqXzFSVf1+6ZmXgHgvzsQMiLv5QJBrQw8D4jRq3EzsLjQHHM+xuhLoqsR0xPcDPCmYoK+l3c=@googlegroups.com
X-Received: by 2002:a05:6402:3487:b0:5c9:1cdf:bbae with SMTP id 4fb4d7f45d1cf-5cf75516e8cmr2629611a12.11.1731591541544;
        Thu, 14 Nov 2024 05:39:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731591541; cv=none;
        d=google.com; s=arc-20240605;
        b=OpTGeFspIyr5g7pERQ9p6bmINFs5jV8LzM2USWQIefBEVnmET8IsKsyFLdLDp5yBgA
         aBqIR0z1LljPVwMCHH/zfrj9+TpK5ynEmRRv4z0FFmHYw3fILgw4QJCIu9jLKfEyffSb
         7KJkNfM6ss6inmAsYqc50DenTdqO8DWJPv/6v4/yqLBdOWwKLbOiu0nkGPSzeTHsi4vP
         AqLUsPv7s5DY0mihsg4thDeMEodOlf7M4MwNIHRAXl1rFJP7uxocfB3j2mGQPPwdRte4
         XDTktWL8VLVQKZrFDBTMDw+76sArG6gvLSU+NWLmTaSr4sglnqrFz/LkmH+3OhPfrOD2
         LKcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=plbMqImFhCJ0rUEwt/xe5Y/dkXS3RPMYT6mE75jOpVE=;
        fh=yuOyWeHKn3aPnN/I4liof7UP7P/dHTYHDw92anPtzr4=;
        b=fsBZnOl64PesBSGPzM4Ut7cIAn1SVdip0dE4JRg0t+qaKv6Bz26KxRksM+uEhx4U52
         CMR6XkF2Hhuggz4yrzDiId3volehot4aERJlM3Znj6e+XersPrbODURe3dZ6vgG9Y6Xp
         lT09m+2zHEofHho3G0D01NhxSwYt/QB9wLpsvF+9R9CcjetKY6wkUDz215RHygEytDn5
         0qAdWW4Bzdz87rTtSs4aFJvlNXh5JM5qTnWc1AT8Z6JNh6dkesIhv50OdixmG8L/YRp4
         JJCMTBWHZ+ghvQuO7dCcjWC/UakzsXgO3NiXkvBTSiFxCV9AwrJannrz1NaemnzdXw1Q
         T1gQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HTeoc2xE;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x133.google.com (mail-lf1-x133.google.com. [2a00:1450:4864:20::133])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5cf79bac6a2si16102a12.2.2024.11.14.05.39.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Nov 2024 05:39:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2a00:1450:4864:20::133 as permitted sender) client-ip=2a00:1450:4864:20::133;
Received: by mail-lf1-x133.google.com with SMTP id 2adb3069b0e04-539f53973fdso520205e87.1
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2024 05:39:01 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUfskBB8PIwsFRnaNoxjUZHwfm7oUIK/h7Pp9EFigdRhzkvOtLtmOmnN0e805Z1+O1c6Dv94AnLUDY=@googlegroups.com
X-Received: by 2002:a05:6512:4014:b0:53d:8c0d:8513 with SMTP id
 2adb3069b0e04-53da47a57cbmr1114776e87.8.1731591540635; Thu, 14 Nov 2024
 05:39:00 -0800 (PST)
MIME-Version: 1.0
References: <20241016154152.1376492-1-feng.tang@intel.com> <20241016154152.1376492-2-feng.tang@intel.com>
In-Reply-To: <20241016154152.1376492-2-feng.tang@intel.com>
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Date: Thu, 14 Nov 2024 22:38:47 +0900
Message-ID: <CAB=+i9TBMmq5EScWnNMHJAFqSxT3_wWkgJe20d3_w2D148gDVg@mail.gmail.com>
Subject: Re: [PATCH v3 1/3] mm/slub: Consider kfence case for get_orig_size()
To: Feng Tang <feng.tang@intel.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Danilo Krummrich <dakr@kernel.org>, Narasimhan.V@amd.com, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=HTeoc2xE;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2a00:1450:4864:20::133
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Thu, Oct 17, 2024 at 12:42=E2=80=AFAM Feng Tang <feng.tang@intel.com> wr=
ote:
>
> When 'orig_size' of kmalloc object is enabled by debug option, it
> should either contains the actual requested size or the cache's
> 'object_size'.
>
> But it's not true if that object is a kfence-allocated one, and the
> data at 'orig_size' offset of metadata could be zero or other values.
> This is not a big issue for current 'orig_size' usage, as init_object()
> and check_object() during alloc/free process will be skipped for kfence
> addresses. But it could cause trouble for other usage in future.
>
> Use the existing kfence helper kfence_ksize() which can return the
> real original request size.
>
> Signed-off-by: Feng Tang <feng.tang@intel.com>
> ---

Looks good to me,
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

>  mm/slub.c | 3 +++
>  1 file changed, 3 insertions(+)
>
> diff --git a/mm/slub.c b/mm/slub.c
> index af9a80071fe0..1d348899f7a3 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -768,6 +768,9 @@ static inline unsigned int get_orig_size(struct kmem_=
cache *s, void *object)
>  {
>         void *p =3D kasan_reset_tag(object);
>
> +       if (is_kfence_address(object))
> +               return kfence_ksize(object);
> +
>         if (!slub_debug_orig_size(s))
>                 return s->object_size;
>
> --
> 2.27.0
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AB%3D%2Bi9TBMmq5EScWnNMHJAFqSxT3_wWkgJe20d3_w2D148gDVg%40mail.gmail.com.
