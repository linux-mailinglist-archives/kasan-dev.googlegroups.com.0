Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4WY4OPAMGQEPJI6JNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 98AFD682A6D
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 11:24:51 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id r11-20020a6b8f0b000000b0071853768168sf4311425iod.23
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 02:24:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675160690; cv=pass;
        d=google.com; s=arc-20160816;
        b=LFR3dlTltjaFytN5WYhRKgNeoZu8/jDqK6PAE5tDDqaBjO1BpFnB+z36pjQALjzC5d
         ZnabRAxSzU5+KBopip+PTghJGCVAh9YWt8o3r4KEm28TIS2dQMorE2XRmLO9GWiCksuL
         QrrQ79x/mbtOffX4kDysodMoIvjeeh+rrDBUmdAt8TIak6Zf49OKlm4vOL50zv8MS2nQ
         MT5DjsWfnzRz5YFS7LOMZ6eDrE+B044O5tXioC9TN63a3ASt3vSiXkXwkPv7kuMY1lZi
         8rKFKArlCznHRsS14b90VaKCY8GFbx6oGw6HoI+qzkJ3o/H6r37FcffMsTUdDLVnPB++
         VNBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/QiHXYsgMZNlN3HyV6pBz/SzZ6GCRwbDQrorsmro0CQ=;
        b=YtN37oAXc2gfScvg4gTVHPqtHGd5ekziByfm2vHcPUMiY4LglXILACGzAIV9H21gk2
         uiYwqDOcPSEms1Frld8nUQSmKbhAbGUKggzumTUt3nouZZPD6GjNr09EPbhnpEgnUpeO
         hVQnSed0aLJSB9RFvkIUiPbh/q+zLQj0t7hDiccy61fGdLyloCNZu6vu4bB8cD60gnwr
         RPePYkUAmzMGq66MkIyt/fAkZpmhD/60FhQ0Ya1oSQrx3t5W9MYsi2JRSilU5LHoSPvK
         iIXGvsDF/LR8gcs8Q1sO+/WGjNVWPZdaZH2geU0CkWP/yu5vLM1GaPiRXGCalnoZoIMu
         LMew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pPJJYCFJ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/QiHXYsgMZNlN3HyV6pBz/SzZ6GCRwbDQrorsmro0CQ=;
        b=GrNe5p3lbYGuWluS/tJacSumQAAtqi3VVcqgeMlHFVLIG6OHlZBeRWLGHe71Hx6RI1
         z3NvR3O3etz9a11I5NWXjkfQc2EDWjMc19bGIsJRd2rOZUjuNLpmM1XWnRfOr29DqUkz
         bcK9SutOmXp7kZmqKn/RvbhtdSfOzPG8xucEfF06LBU9mMjBFSEJly74DlnmKPKQWfqt
         3QRxr2Q6cGnYNh7jsbHVFrSG4HYvjPhhYUjs2rx9qWiYWvYIljfqwxaWXqRc+qQkVAOb
         FlK/yAkAsf9At4rHjTWeQbDTCp3gCsyKri599el3I1fzYl+t+TKFvmtOdgFuixtVh93G
         u3aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=/QiHXYsgMZNlN3HyV6pBz/SzZ6GCRwbDQrorsmro0CQ=;
        b=PmqayFdLDiZrkigT7iGryGvW59MGqDj4D3f1A3dCGIhfrq4iqrHUqJiPGohJ5gM52V
         xsiuVrC/NsPZ8DRyM+DT+Um3ZPxib/iA7MdCdy0I3zBvvDer86apK6wsMox/u4RzLQKX
         HSTD/xJv7B/UXlZA57QyxTCMij23R4cvl5E5AKl/y+icZmT3qck8TXIWA8jmBKdWEz18
         bX6c1tXvoz3agImNXhyVW5HKdyrbcy88D6PJKh49otcELSx8oklhJ2qkLKeCVBZbIov8
         /AXv/eiEBy5HXKt+2S87Yel9GissqyXgcpqHtbkU/C3z0ZtbXBw/eJs0TFQMKaW1dHAr
         +yXg==
X-Gm-Message-State: AO0yUKWgTlXfiSBWev3PbGW5s75RK+BNV/Taub3XF4g33KEDFdUJpqHn
	GDCnCj+4NKMAh85EM/JP4Nw=
X-Google-Smtp-Source: AK7set9ZXQlihLTvNJt34oIOgz2QMWl8C6Img/ATl4X0b4IUJFiL6BlnhFAKWXcpAnd13UiOUjmheA==
X-Received: by 2002:a02:c50c:0:b0:3ab:2dab:b35d with SMTP id s12-20020a02c50c000000b003ab2dabb35dmr2586940jam.80.1675160690148;
        Tue, 31 Jan 2023 02:24:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:d618:0:b0:6de:9e24:a442 with SMTP id w24-20020a6bd618000000b006de9e24a442ls3081946ioa.9.-pod-prod-gmail;
 Tue, 31 Jan 2023 02:24:49 -0800 (PST)
X-Received: by 2002:a6b:e608:0:b0:712:d45b:858a with SMTP id g8-20020a6be608000000b00712d45b858amr7663841ioh.6.1675160689669;
        Tue, 31 Jan 2023 02:24:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675160689; cv=none;
        d=google.com; s=arc-20160816;
        b=Z56EdSZAUWLYz8necDbTrEJYOp037QCH+GoD9PswqJ9mquxlyTyMhDy87yPk1K1i1q
         E/okDO0J6AV3KhmwqNDTvEh9oNSRxMMtijiRT8zHloDadYMAir2z+9iNjbqspbwkWj6W
         hGU9xjN6+dAFgaMKTKa/3NcjEH4hmjTi//AkuS/fVYoTIN9HwoXZIuLbZTKYe+va6wkV
         J6iniKX30uHn51HFm+M7sV/eIxPEIvSwDohXbRwiXtipfe8dAPIi2lFW8Ojm7U0KBGRS
         J1lTRf1FCQzXJG6PJyhPZo7PV/wu+avzWeK91A4WQAFAiqSoiIN4quB/cPw78C3LYa7q
         V7FA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FW/XV0xd0Zhp+J2b4xgsonMeFUqp3Uw446N0MlnvYG4=;
        b=fRxUx+3eHmiL8ffzxO68c9+DjHYQ1/Hv8tbL15MmtzSZELXjsSBdPPMwi9cV+KCuAo
         TOtgFOTb8so8ppHsLk38EJkvTOw/qa/zm6+uo83+brmqxCpa5XPGrrKKip+J6r0RydOa
         TKAcCS2MDtTnG1/+VtMpirUloAVEm/cuIsUVpsDVgocs3+wqNJqPy2ZZsHX91jjl6jki
         Rbqqu0UzI9NcXQXLCg4eXw1eiE1EFPhkDEkszWE4q1O2gVczqOI3YjQVF5FVA8o04ZJz
         PrK3KFPG2z4B+wBo4FlKQrQFgapRbK1kzPvOjoXp7+xWvwRi/uRkuRP0x27gv1BOvriz
         avrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pPJJYCFJ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa2c.google.com (mail-vk1-xa2c.google.com. [2607:f8b0:4864:20::a2c])
        by gmr-mx.google.com with ESMTPS id h18-20020a5d9712000000b0072063085913si141247iol.2.2023.01.31.02.24.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 02:24:49 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a2c as permitted sender) client-ip=2607:f8b0:4864:20::a2c;
Received: by mail-vk1-xa2c.google.com with SMTP id u199so6612990vkb.12
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 02:24:49 -0800 (PST)
X-Received: by 2002:a1f:a2c3:0:b0:3ea:4830:a019 with SMTP id
 l186-20020a1fa2c3000000b003ea4830a019mr892642vke.9.1675160689238; Tue, 31 Jan
 2023 02:24:49 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <3600069e0b0b3df602999ec8a2d4fc14fcc56a01.1675111415.git.andreyknvl@google.com>
In-Reply-To: <3600069e0b0b3df602999ec8a2d4fc14fcc56a01.1675111415.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 31 Jan 2023 11:24:13 +0100
Message-ID: <CAG_fn=VwsMC-Ddo3WViQOBMw-W4PNGMRAguNP3OMmQG7s45qEA@mail.gmail.com>
Subject: Re: [PATCH 03/18] lib/stackdepot: use pr_fmt to define message format
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=pPJJYCFJ;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::a2c as
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

On Mon, Jan 30, 2023 at 9:49 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Use pr_fmt to define the format for printing stack depot messages instead
> of duplicating the "Stack Depot" prefix in each message.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DVwsMC-Ddo3WViQOBMw-W4PNGMRAguNP3OMmQG7s45qEA%40mail.gmail.com.
