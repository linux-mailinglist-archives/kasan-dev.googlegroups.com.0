Return-Path: <kasan-dev+bncBDW2JDUY5AORBSED36GQMGQE2CG5YOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id BD1F847371A
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:57:29 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id e14-20020a05622a110e00b002b0681d127esf24703154qty.15
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:57:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432648; cv=pass;
        d=google.com; s=arc-20160816;
        b=UdN8c6fceHxtKpOyPQIZ8sKoyGkG+n4yIBqMluQecY8Oh+BZ6Hy+C7rQUrxRpzydo3
         mD2Ng4PwWhh9+yfFihbmK4Ly9NcMD6OKs3GGgttW0Va2eme6ekDrsP7FzYlI3vg/4jdu
         cOvqZiJOIAfrOvTUcpmRBKsUJMUQVtDFAzQ5KKHGMrySIaAojkp7hFC6X9gMtV/Nqvu9
         AmFAdWaYuQXW2v6B48XyMkKek78rFKNzq2V1N5v5gfShiAdxSp5k7LOWs+LRF08AlSCK
         AjZl61miLEUe/86Jt8g1XF1Batt74QSeVXvIKXeMlVe7bQ45/i3Zxt22sU6/MqDIy8Kh
         /VEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=2HFcQZrhJxMI9M3OLqRhUD4zMAdUy07E83F2paMOPgQ=;
        b=iqqOswabI556E0wBHlWe3pEyhkAP+4D36qNAOxYk3fK0pRoCJCApeAlLMOvE96XrVL
         PcB/KAMIlYhKW7hlE6Q8Hq8M9R0/Vq7bnenOphK1A++WfQ8r4OMlzi4p/Rw2zjjKmpcb
         48B9XnLh23tvic9YI4uwGB5l2lmhzfKEAk0EN9LlwlxLwCoFicITnqakxnOYuhEqRtyi
         4/c5n0j0DydqdDASYwM4v6w+9YyMLMe2aKVZg3FFW+R6Md1FBZf8ZSUn+/af3+4sYADS
         ukNantzyREVUrrIGPYHgff7aHb1Hj2eAW8DvAANuAmQuwU1cOQK2WtAe4eNxXWB7Cdqc
         m1xA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=WGDhTKgs;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2HFcQZrhJxMI9M3OLqRhUD4zMAdUy07E83F2paMOPgQ=;
        b=Ci3wx8by2MQETegglglIn7WDID0pm22VfkjCqBrDClT/OzdseVYwqYwzSDyoeHN5ju
         ePar/MoPMRFpH0KNZJ1dflmChU4gigX2eydHga9sNrNhRG+KqIh+Z067fgNvJPJPnZOY
         afez4R2KmfqAFPzYhuOuAy7mBoTCMmzBjSP/V8y0n4g0DuZX7f3HeHwZ1xN1Gc8EQou2
         ryQpQUFecqcAtRvlaqEDMM+Hv8hmW2is4hbK7FjXaO30UB2E7qACv2QhA2sZVyqb4PW7
         MjWFM3t4wRQIzFuVvZgYYd8yI/kSymJTgi1wK0PrZ+rLmRmnnPPIMZs643slB8I4KlgP
         WLSA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2HFcQZrhJxMI9M3OLqRhUD4zMAdUy07E83F2paMOPgQ=;
        b=dXTezq7ZEv+yFzuRD9w0J+ENw4HIjXOfhXDj7j9Uy8NW4/P0AusR09Y6E962q/botN
         POF8hkMlRUVaVKNJycERe8SQq1QjLJetyVOiq3zetWw6z7H4ZVleJRE87XuxMyTfnCYD
         wMGFSdUjZQCV0zcwXX36Er+KyyT2K5y7yJ3P5X4IUPx3ccfWL7GYwtDJpsuD4ZlvnIVc
         BFD5YA/mur3kzGaPe9dpEcKR975EF5p23LIPy7i2ESRj7QiY2HIrMRIxLWNUP//vP0C4
         +GjTA7oGIAaggpHUbQYsD6aY6IjZh0buvDsiRZOM7j011SKkzTtl/uK2b9TttxN75c1g
         wA/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2HFcQZrhJxMI9M3OLqRhUD4zMAdUy07E83F2paMOPgQ=;
        b=Vv6ulupxaX4v2NgcGINKT6D41NLCAQnPSCiRXaXfRDZsXSjklpPskKt5+Jakw5c+vi
         SGdCShc9mbTkvT4t9Yo/NAJvcV9EUU8Yyp3E+M+1UUazMQ/5ocSGOGCrmG8kOH98SH4b
         yktcbnVTxcDFAxY/M71yVgYVq0EOiQmZMYaNCdM2lyQ9nmofkNGYv+xOhe4/l8I1mf1d
         M1AvFedDuTHKsSABTyiCmMfmL9jfgZ5kBbRT2PwNT6fFsYsbHz4FgXOa7KOOrpeBmlQl
         G3827xs/WlZlnUcGOaGE0gQGbzLmZ2+tXolzZOva2QCZ1/yF9RxtVdx6pGrnJv3qxF5y
         0/jg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530uTIMOS6Lz1o2ZAW6XVcDXo/7YAQbH+sl8hEJyWQlGxCl8kgsd
	bSgXV4eFyOGJd8XBh4aov8M=
X-Google-Smtp-Source: ABdhPJw6RLOATrEBeKn1kDilqsmP4DU7AiTCS6sW1LmGl3WS8gRC2YWxQs3YqbmJVIoqZYL00jqqrg==
X-Received: by 2002:a37:a50e:: with SMTP id o14mr864389qke.288.1639432648363;
        Mon, 13 Dec 2021 13:57:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:8d85:: with SMTP id t5ls9893417qvb.11.gmail; Mon, 13 Dec
 2021 13:57:28 -0800 (PST)
X-Received: by 2002:a05:6214:c42:: with SMTP id r2mr1232416qvj.70.1639432648042;
        Mon, 13 Dec 2021 13:57:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432648; cv=none;
        d=google.com; s=arc-20160816;
        b=jX6ZFOtqnr21fdG3U73NoNI+EJYFV3ADlXj7saWOgp3rZWGMcDSSpukJRKDi/j7NcV
         m+lS649jNcLLY9EdnWI76dwLKc//U0H2goW2jwsvQPv6Pe/zra5AJV3v6O8FSWwnNACf
         /oC4lD+I3PKNuymzljLJ1X9b1Db9zmhSB/vlgf5z6IxPPacgEoEcYFEkN9kEW0PMh31X
         fWVkBDLE4H168RQRYucM8TBz4k2GaF5kNh7ZttEZjS/mZrmFUpPdGw3mdCQ9bvYqMYPR
         MWf5D8ys59INqIk1+mZ5zXwfkgkbnvG8RLeMO3ZN1hTDBRj/mZQHvnUzrbmm/jI2OZq/
         z5Tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mm2UWj2YnKjrM1uYfSOmZBTk8qAIxqBQ9/EkHyLqgsc=;
        b=J8UWua6Kdlp0f0X3DrHU5IKC7kDqInmkDkKJBJ0kgf8MXwFQEwlQ55Knlz37cyJeon
         lThokS6AStJ+gV2RSs/2Z0BL25kA2azqRyp223oQpR/h+oLG2eT+PtnWOLsJ3rW72/we
         oAyf230sHH5iMXNhBVIvsNDxFegdYISjoYygi3Vt4sc1bWdfdOUGZxu/bGDt5bPqpFnn
         SEBdA8/ihd4Voak8nQCg82BSgOHaFb/PPMti+wbBfT3QPXk+GfBZifvRoSwd1wOVYUbk
         66uhglI6sSSkEy9ta6iIliV4IbPLeteglY1EsK80InfY8LwCZaXYrrZe0VLEUVPaFlCX
         1eNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=WGDhTKgs;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd35.google.com (mail-io1-xd35.google.com. [2607:f8b0:4864:20::d35])
        by gmr-mx.google.com with ESMTPS id bs32si796845qkb.7.2021.12.13.13.57.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Dec 2021 13:57:28 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) client-ip=2607:f8b0:4864:20::d35;
Received: by mail-io1-xd35.google.com with SMTP id k21so20623797ioh.4
        for <kasan-dev@googlegroups.com>; Mon, 13 Dec 2021 13:57:28 -0800 (PST)
X-Received: by 2002:a02:830e:: with SMTP id v14mr555545jag.644.1639432647604;
 Mon, 13 Dec 2021 13:57:27 -0800 (PST)
MIME-Version: 1.0
References: <cover.1638825394.git.andreyknvl@google.com> <a1f0413493eb7db125c3f8086f5d8635b627fd2c.1638825394.git.andreyknvl@google.com>
 <d082aa66-8b6b-2a32-bf7e-8256b9ec3cc4@arm.com>
In-Reply-To: <d082aa66-8b6b-2a32-bf7e-8256b9ec3cc4@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 13 Dec 2021 22:57:17 +0100
Message-ID: <CA+fCnZcY+1xqiTMfwn_NwptsZdK_jW3HM71oL6yQ_3+LOK7Hyg@mail.gmail.com>
Subject: Re: [PATCH v2 24/34] kasan, vmalloc, arm64: mark vmalloc mappings as pgprot_tagged
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=WGDhTKgs;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35
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

On Mon, Dec 13, 2021 at 4:17 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> Hi Andrey,
>
> On 12/6/21 9:44 PM, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > HW_TAGS KASAN relies on ARM Memory Tagging Extension (MTE). With MTE,
> > a memory region must be mapped as MT_NORMAL_TAGGED to allow setting
> > memory tags via MTE-specific instructions.
> >
> > This change adds proper protection bits to vmalloc() allocations.
>
> Please avoid "this patch/this change" in patch description and use imperative
> mode as if you are giving a command to the code base ([1] paragraph 2).

Hi Vincenzo,

Done in v3.

> > These allocations are always backed by page_alloc pages, so the tags
> > will actually be getting set on the corresponding physical memory.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>
> With the change to the commit message:
>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcY%2B1xqiTMfwn_NwptsZdK_jW3HM71oL6yQ_3%2BLOK7Hyg%40mail.gmail.com.
