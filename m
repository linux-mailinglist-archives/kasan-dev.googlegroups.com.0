Return-Path: <kasan-dev+bncBCCMH5WKTMGRBL5SVCPQMGQEADPJ4BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id C1DC46943C4
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 12:04:16 +0100 (CET)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-52a8f97c8ccsf121153257b3.6
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 03:04:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676286255; cv=pass;
        d=google.com; s=arc-20160816;
        b=PUSYNHzd65Cfs23peu7kulo9rzCBVbajucKk5SIHArTN+ea4aSJNO0fmNan+sCqCFv
         OCFuMvyUapxbBuddEO59sahqgsz/2L3LlFnHLGxoCbsph9TNB3DrzZnDLhkfLYSXHoWa
         PdTeCpP6soqeUti0U/FAk1b3SlLIdpJfNUmP7JFEtZJReLfAR43LtSj7UeRGNMm2whgK
         SodL7s1rTUZxaEOVacj3Anu7/Pb9/3oQ+WFDZg+Xv60gI2GoWKJeeY/BEnywQ26p+vj/
         Eev4B4KFAVV94hcMT8UGPMuf+Wh0J4jsorB6E5PydaM8D6ihcoAJjpgGJYsmReWtCorT
         k/Gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7vUfED5ThlQ0Bl/mTBNwCdmokDbGKVwuACssAFOiLus=;
        b=GecsbPPtGc9URob2TyE7e+pnwsZiIwKW6UcqW9nPKYN/ya+Vn2NKFNYJtnqEPBoFa1
         NhntuEbWvpq4ZCM6MqtymgSIKDjqBdxdCZoQ4ylOZV0hrgHVO8+xWwxjXb4qo3Vsonw5
         bUo1q1l7icpjL+y1UN/9NHOTpxQkR5QGUqSQJs0NQ2dVc7KcO9uvF7hu+nYSf4DRNi0+
         0QfYoVbNLhzXCyvFOXaRmsvSq6iwNltDexSaOqbGrzjKbOF2PNNMNJO1/UJdPdyLkpp7
         Y0gD8xyCHowBAvNfI8nfEndZG+AIl0CfkLAfxV4e1IyC/fEKKHUlFS7Cbabion3WC8EO
         wD0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=j4ZA5Qa3;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7vUfED5ThlQ0Bl/mTBNwCdmokDbGKVwuACssAFOiLus=;
        b=pAUeyi6jR8Ed6m6+SHySdo9LkYBXwi5/0gtbgZmvujT/MZj/bYFnrhKmCpkx9ML+3E
         6ZahkFY7yWozjL4iATW520DjZS8ktshZxHHUfZCEqbT0qkUKRUl3zTS4HhLkD16NBoKZ
         kfaK+W7M0V6aL9HSRC7Jx9oCvToLdUtS2CaGEfACJpyysLCx6CROFS9wTIF5osJsJDHr
         OPhv0WvWUhMFIIGonhjyTdlGdBY721v8qaxLSO+tUBw9BreU2YLDextwtw11Lu7OAd/I
         XpJKPvOMiUL74lhEBoZXkNHMDau+Y60OsAdz6Dg2aW1C+wV4VwvY34JszZOUL3PMaR+Y
         Uxug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=7vUfED5ThlQ0Bl/mTBNwCdmokDbGKVwuACssAFOiLus=;
        b=bBI7jj9P6E0Xsx9wJYRReimmhO3WBrmspqLj5ikqGXx9xfA+KcyEFqtfeHrDLKiQAd
         C9pDgk7+OJ/G7vibu8F7nUoIxi+Wlj2LRmfUOHRwwuI4dV/Xjh2RVqiHTDW//NmFny8S
         8vgnc4clRnlrxCsRtGBHah7tSdaByFP6MRICSHiA2AginxZueUoAjE6u1GLUZv8qYCnm
         JvmuXypIq66CY+2qJmgSc1wYx76c9cs6z2uBdbIN/SMVOI9yErWSEIy9AgkDCNmL+XEx
         xexcvJaMvrLAGBVbqaaWOGIkrKEDlFk9cf1e0VBvp55lXyp4j6lTM56rK8LZiahvd0/3
         41Xg==
X-Gm-Message-State: AO0yUKXt/ReIHSr4qlYT3Yi4PwkhlV76Y7Buk0udVSSaNDT3aMs1Mbuc
	MxsflrUTfEJsF9CHHmylZyA=
X-Google-Smtp-Source: AK7set86HJ6VFXlECozfIsl1JNtyxPufacxPHWdxgKbz3NRTK8Eg5NBA+VqFCfHVL1rOAvaZidJ9og==
X-Received: by 2002:a81:8745:0:b0:508:a182:3be3 with SMTP id x66-20020a818745000000b00508a1823be3mr2867238ywf.432.1676286255517;
        Mon, 13 Feb 2023 03:04:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:50c6:0:b0:8f2:6ce5:9b39 with SMTP id e189-20020a2550c6000000b008f26ce59b39ls4908658ybb.7.-pod-prod-gmail;
 Mon, 13 Feb 2023 03:04:15 -0800 (PST)
X-Received: by 2002:a25:910b:0:b0:7b9:61ab:a7f3 with SMTP id v11-20020a25910b000000b007b961aba7f3mr6045270ybl.42.1676286254924;
        Mon, 13 Feb 2023 03:04:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676286254; cv=none;
        d=google.com; s=arc-20160816;
        b=hfiEChlpYsS/xhtGcc7PjvjCuvjQLC0gIJSPDOoVFpn8RONJl83hkIJbAjFTP6WpfB
         04Bx2K03HKDQeBohiyFIL9FMBL416dibq1C7lPyFLBkVRpn/8evMBeA8+hKCpLukU5ys
         AGAGPZ6mjk3Sn92wPz3A0vaCtqc0wdxcL5ambQmRqHe4tNX6DIttRt7l0CJ1kHQDsOQI
         hCEPIKjpXIbdsQqOUlAnT5eAJexzwLTNeco29KOZByST2FSk2UsyhnNHs5Gz5cLivdhL
         hU+tu29LA+29wCvpDRuDIqqbFtgE6KO/XfU9PpUPeTtONTm8dEn09iuqRlPeAkgDEW9Y
         ZmuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NYx2AyPU7S06WvalHgphXS88wTsCd0bUzbIYrlIqVZc=;
        b=Z2CtmK6DcdrNE9jK50+0M2m/1ccmbqGTskZ5PmjxUm4AEuZKNG3UB2xaD9gon60Ata
         K28ISskXbdddptCyBL+ZHDJy54u1mHHlEB9FE7/Q0px6FTIbJBVZYHi5A+w+gP4zMXcr
         Xdgw7wE5TbAWi6qItGmPOJ4R3XI+fJr0EqCuwJZkoDj6ttoF3OdTZX99RDL5s56yKTtr
         pB8t85gndEUMa1AVBiw9VpwSsUC346fT93gtDh3PPYxdQ3A9jpeIJaEFlmduu0DMBHEZ
         mG7SxkMz+LUxoEs+syYrTDahP9zayRAGg04EOFxwm/Jk/sGzlgvJIgEJOFtixV/1COsE
         +8Ng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=j4ZA5Qa3;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2d.google.com (mail-io1-xd2d.google.com. [2607:f8b0:4864:20::d2d])
        by gmr-mx.google.com with ESMTPS id m17-20020a25d411000000b00898c1f86550si1400071ybf.4.2023.02.13.03.04.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Feb 2023 03:04:14 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2d as permitted sender) client-ip=2607:f8b0:4864:20::d2d;
Received: by mail-io1-xd2d.google.com with SMTP id w24so4315460iow.13
        for <kasan-dev@googlegroups.com>; Mon, 13 Feb 2023 03:04:14 -0800 (PST)
X-Received: by 2002:a02:a794:0:b0:3ad:3cae:6378 with SMTP id
 e20-20020a02a794000000b003ad3cae6378mr12249003jaj.16.1676286254268; Mon, 13
 Feb 2023 03:04:14 -0800 (PST)
MIME-Version: 1.0
References: <cover.1676063693.git.andreyknvl@google.com> <f80b02951364e6b40deda965b4003de0cd1a532d.1676063693.git.andreyknvl@google.com>
In-Reply-To: <f80b02951364e6b40deda965b4003de0cd1a532d.1676063693.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 Feb 2023 12:03:35 +0100
Message-ID: <CAG_fn=VbGHm7WFqvauZ6-RnjUuk6pZQb0Ac61bKshQSRDujv6Q@mail.gmail.com>
Subject: Re: [PATCH v2 13/18] lib/stackdepot: annotate depot_init_pool and depot_alloc_stack
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=j4ZA5Qa3;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2d as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Fri, Feb 10, 2023 at 10:18 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Clean up the exisiting comments and add new ones to depot_init_pool and
> depot_alloc_stack.
>
> As a part of the clean-up, remove mentions of which variable is accessed
> by smp_store_release and smp_load_acquire: it is clear as is from the
> code.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

Thanks for the cleanup!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVbGHm7WFqvauZ6-RnjUuk6pZQb0Ac61bKshQSRDujv6Q%40mail.gmail.com.
