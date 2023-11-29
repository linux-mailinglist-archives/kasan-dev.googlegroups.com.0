Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSMETSVQMGQE63ZYP7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A68B7FD245
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 10:20:11 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id 006d021491bc7-58d8e773afasf3027234eaf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 01:20:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701249610; cv=pass;
        d=google.com; s=arc-20160816;
        b=PhTV12SdQlbIPlJw9J2lN02TV5YibnKe0i8RORSwDdN0GsYyG9z5cTY1l7h4HzIdzo
         IyN2hX8X9FAHLg/Ft9ajQNkodtHPI1goTVcugiz0CICmQwFMQHc7zBZXioXQ7mcBerJ7
         BT4uuvzjquAUYf50/+F2FInFCdw1+Iouyb/BqZlOIwrZFg5AG2YBYF2th3SdVeNAXdpi
         ZnfCkviAPAzHBcdeDvsGzNn/eFKJy3Pg5Don6JJAom0ZdawdjdO+R7wJFp7IWhR6C3HK
         pPch4s7f4DkwVSHv1N+P7Omb8gigAn71J9VSP9STzPlzJQHnmla+ezgJUVOfcyrIrHwa
         eNpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8/9+eeBdK7lxnIt9JgMviFsXgVL/rdM+1lJ7DMtlmnA=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=pQ+0thxYeZv46mW3pHgoHo/pn6qQP5bKvaKOM8u/Ir9fZa9V8KUfita66SlAQ2tBmF
         rRg1mnzaLtI/9/KsUJiYq8sphfhdGNT+p949XB5vSP3p40tkBOzaOGhOI1dWob6iydu+
         YarBQEln01G2oPVpmavPMlLf+Ry934u4dMp2se0G6QzcbFASwGMNOc5oEAYVZXJDHJ+9
         aKQL8sxp/VKY750hkdI8v7UIFIL+iiq/jC6l1sJgARKjBsIx0zVXukyd7jAcS1TEgnqd
         SZdIk6Rt5719Fx6yd4wAeL84DZXReT/arqs7APnVuiJnd2GsKenHcWuX9MubKiVk9GwH
         OGbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=niOm0ivw;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701249609; x=1701854409; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8/9+eeBdK7lxnIt9JgMviFsXgVL/rdM+1lJ7DMtlmnA=;
        b=ddMM3ZuV4BDVfggMQkdgwFu/Qxx7Gym+aKGfzHBQrZy2EHGCRjL30nsngEcA8X5sha
         KuPZP2bZO7pYldJhCNjt1zBZewJL3cngEWdidPnKazAce/K1BwO/WX1mPjIJ8jlH4wE1
         LmJKP/px7XEUGYo/UDRuIwOI0RsfvzNSEGGFFZw0kChWMt7a3295E2l0rUr+c7zTB+za
         3MU0lzf6umhzc2+ADZZe7i8uebA039GFvP8p7UyV+J23C1yIS22771iJ/mKKa27h5fxW
         ZSYOY87+I5q7OKIUqsq86iA0n6AsIPK/CfyAyUbTM3O+FOJNHa9pqo1gSLH/uVHBwCnp
         5pjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701249609; x=1701854409;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8/9+eeBdK7lxnIt9JgMviFsXgVL/rdM+1lJ7DMtlmnA=;
        b=NkADvKBImybhiUb7qe9JcJESI4eAimVg1s1ac0Sv9ofaSd+JgW08RqtE3DyDwq4EME
         wlrZgpxzc6Sqjk5mj0vOi2rS/r5H3KBrBy30ieyrZ6zMqUC+8rej5H63yFqcKuoKMcs7
         WJrHOTV/GasQ/R5xq7aeuNq+CjkYCf/lJOgkq9Zqtu/EgoGBpVTJIjmlwyWQIzpbjWHS
         /RSgwDhMcR8BqTNKmopExHo6lzD+KTOgCkFKfm6mwlhSyxrl0qyfO2UqDiD9MTg0xQ3c
         KMhepRL1z+BnLUD5FCEnsML3a5xT+CGEItmWXsWcjC7jpaD0wnVtkq5BqUwDEvuSTuCh
         vlHA==
X-Gm-Message-State: AOJu0YxRwK76mh/oNgbQX01vFNrEwZ8ic80WEGS0bfniWFB0HN9kGbnc
	AK56ZsmP+wMvESJBVMeVpBA=
X-Google-Smtp-Source: AGHT+IFIQw4OhyK15l6Frh/N7SqMHjyiR3ffVu0efsDDsyEfFjHiyKVdRzt1KmunqWKF5midFw0f1w==
X-Received: by 2002:a05:6820:168d:b0:58d:a202:5bdd with SMTP id bc13-20020a056820168d00b0058da2025bddmr8395059oob.9.1701249609703;
        Wed, 29 Nov 2023 01:20:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:1503:b0:58d:d4e0:4e with SMTP id
 ay3-20020a056820150300b0058dd4e0004els182717oob.2.-pod-prod-09-us; Wed, 29
 Nov 2023 01:20:09 -0800 (PST)
X-Received: by 2002:a05:6820:220b:b0:58d:afeb:f684 with SMTP id cj11-20020a056820220b00b0058dafebf684mr5540224oob.3.1701249608899;
        Wed, 29 Nov 2023 01:20:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701249608; cv=none;
        d=google.com; s=arc-20160816;
        b=kSFapLNpMl5Xt0Fw1emCKyDqjnhEp2mRT669YnbTO5cRS/SsXJejU+8jpqhMNteHYB
         UxP+26DrXTAAt0LonvD4zjMq+1/qY/l8+AMXYVBgX7MJKfVBS8wvYYLTW1EDrDPHkFeL
         +axEQ21Cr/VuuOlpohpoJx6z1e2BMza5094CW2rKzWAoGsWMuBQBqp7MQ7Sl+1T8yQBa
         Fq5vFKGAvZrHeHJUveC99Rkc0XJWoqIWW9t+VhE0tpmzTlOS/7Bi3TNaJpRmF0o5JW/v
         kjU7Hhhuu9AO4E7LnJo64qv+SOFuuUNBgLaR84za5dgtdi/rlsmgqRxmVXwWJVnhHvtS
         S0qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=q6jgX+fdtw/9pVukVvzlC00W/od07a5izGjIu/hs4qE=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=EzJjvNOCvMeaYGXZaNpxERf8xNArOO5Ls1xkTYblPjPUaAU1nzewlDMaIrojGNf+q+
         KZAqEJIhDvyVsIfV/yDlEMQ5M4tXMJzfpmmV5AOZyml1zIWJow0g9zBLc0whngZKcTEo
         dWQtxFYwzA5sR3oqv1X2XO452/juuz92epjwjoArsDc7c+D6I7CSrpQRzOcqlgnhxlcs
         UVR0gy77PC530/ORVCWtdtrxb21yTCmILnpmeS5Hp5+jl3rOzMc2YrAlUme3MK11vNQ0
         AjscT4mv2M/vk1Jc7PQVPXPuxzZPbsV4w3D+tdsjPXcaF4gbfennVmq62etfwGIfqw3D
         Vx0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=niOm0ivw;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2c.google.com (mail-qv1-xf2c.google.com. [2607:f8b0:4864:20::f2c])
        by gmr-mx.google.com with ESMTPS id bv20-20020a0568201b1400b0058dd4271940si37461oob.1.2023.11.29.01.20.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Nov 2023 01:20:08 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) client-ip=2607:f8b0:4864:20::f2c;
Received: by mail-qv1-xf2c.google.com with SMTP id 6a1803df08f44-67a338dfca7so24175916d6.2
        for <kasan-dev@googlegroups.com>; Wed, 29 Nov 2023 01:20:08 -0800 (PST)
X-Received: by 2002:a0c:fccc:0:b0:67a:492b:6cbd with SMTP id
 i12-20020a0cfccc000000b0067a492b6cbdmr8165414qvq.6.1701249608288; Wed, 29 Nov
 2023 01:20:08 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-34-iii@linux.ibm.com>
In-Reply-To: <20231121220155.1217090-34-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 29 Nov 2023 10:19:29 +0100
Message-ID: <CAG_fn=XCeE7JF5hbpzXu2A0Cae3R16_hnDwF0==oJMX320wBHQ@mail.gmail.com>
Subject: Re: [PATCH v2 33/33] kmsan: Enable on s390
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=niOm0ivw;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2c as
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

Hi Ilya,

Sorry for this taking so long, I'll probably take a closer look next week.
Overall, the s390 part looks good to me, but I wanted to check the x86
behavior once again (and perhaps figure out how to avoid introducing
another way to disable KMSAN).
Do you happen to have a Git repo with your patches somewhere?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXCeE7JF5hbpzXu2A0Cae3R16_hnDwF0%3D%3DoJMX320wBHQ%40mail.gmail.com.
