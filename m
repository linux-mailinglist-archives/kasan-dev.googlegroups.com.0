Return-Path: <kasan-dev+bncBCCMH5WKTMGRBNUWRWDAMGQEFDNBKYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D4243A415B
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jun 2021 13:38:32 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id b17-20020a63eb510000b029021a1da627besf1563428pgk.12
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Jun 2021 04:38:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623411511; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZttNP7teSBprXIyErahHbjAKsFn1lRkpbMiRVLLbjqtBCrhqk4brfT8QQ9vH8xwVbZ
         ycsqTO1NZiCX6LzyoDbTy8AzaAnjSHmvfVYSkml05epa6d4OTeA8iG8mUBSmLC2/eehC
         V8OlKnD2pHiuoMemPet0c3dTd84UE5ZY7OBwbb/jYk0SVbAZDLtQdJhiKeqZpS/MtjGo
         u+imcq9gEZ3RQCQOefeMknBXReZc741999myFgqe9O/jVTTjLio2kF2llXshJXJ8daCo
         HJoPiOLfZ9rlx2zN/4IQCTXBH7PVuHIyiLlbsYC8md4nVKiAhmirXNJw4RoroIZD99k3
         wQlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GRVuPRz/0u0Vlh8qXoww7HT2Vn/9ByjGZPP0ipyqzQI=;
        b=Dh+s32NbenbFWhN6zMFq3+XF+bg6mu6HvyD7JtbeMvJIOBJXTvjIQId6d8KWlT3+z6
         8ZfeKL7V8n/bNqrhEiCz9Y+yFeY6LWRWaGaABj2eeVsINr54LhqCQOb5wRLtQMsPmdQP
         D/wv2i3N6/KmVkyilWtY46C1OzAspANrRg1mSBPgnprmf+wsbcIi+/gP/9arc4USMWQK
         HonLk5Sjn5tVBzGPUR3EsjxrfuUUPIrPrsagOgGZapIRSp9724SrWVLdXQ12yORfGgkK
         2R5DJtJyrIbBfKcbcFtKfys+QQyvplarkKSV64q4FDEmLJ9UfaVrzg8wv53c1Ozvgg6h
         ZYTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Jo3ruZFq;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::734 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GRVuPRz/0u0Vlh8qXoww7HT2Vn/9ByjGZPP0ipyqzQI=;
        b=bA7icRe9WaBmu6fdSHw1bgzV4LW1adoOs1s6pMFOeCbVQH+U7eFoLIG0kEQVcHRBTz
         Z5GBRnWM6OBuBrdp7ftUsFoKnNLTiO8CVflvkph3NpxjPj8PogWJjSfRlVs8YB78CIDN
         JX8CNnczFk48hQ2VZ7pA+i3GnYWHL9nnkfRBdc2K0RZytk5C3NZyBT+cTwqUqR0se/BS
         kssOxX0R95vTLWZ9sKkPvRMWIJJpppqfrmq1EIFqOaEiUPz07bbnwoGxKHds9hlzTKtT
         wWE1IocCZN5NC6XSAbU+//Yfg0mZP8KOHTqp8KMDgqNdrQJ45qwKapr50Sq4TJmEJjm7
         kMyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GRVuPRz/0u0Vlh8qXoww7HT2Vn/9ByjGZPP0ipyqzQI=;
        b=iogyADQuLy7x4KQ0pgRMPAdfp7jglv7Y4fvQNBiUPNIlcSl33xC3YZyxw2BAcO3gSk
         yJOQxy1eUlKL8hO0dRcubnF7HV+7VHmZ1Vdf8XMG45ubkkrC3/5Jway+2YcmcDJJe9XU
         IXI3cYEb7P2gPGVpIkeK1nvhs53jLXg3Rol4HHJnTVjRKAq4ADsPyYAiuIYdpXuTDW1u
         Rsl6KPOqZAYI9gY2e6kdXztslt+EpMO01AFb9f9F5pMw9BlMHMZKwdPRXIb15Lu0mjfv
         8MhWer6G+7Zn4y79S6Iw84p+Jt9r+6Bw/Dl06/v5b9LOHdHVUzWbAlIZC/LLvI1drLjm
         jUJQ==
X-Gm-Message-State: AOAM532qvt7DMiaULdCVIqIKdpX7uIUeXJKA/u1zJVRwtENEqxctIeuv
	tcurjDg+Ss4vbFx0DK64u9w=
X-Google-Smtp-Source: ABdhPJynddJjh4dCQLlQ17cICMVq6DI4p1ksfNQ/FzHCOKQ0Zcl7lMqGPs/enYaCxzQWoU2jYZmNEQ==
X-Received: by 2002:a05:6a00:234e:b029:2ea:311e:ea9c with SMTP id j14-20020a056a00234eb02902ea311eea9cmr7713748pfj.36.1623411510730;
        Fri, 11 Jun 2021 04:38:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:51cc:: with SMTP id i12ls4289081pgq.4.gmail; Fri, 11 Jun
 2021 04:38:30 -0700 (PDT)
X-Received: by 2002:a05:6a00:124d:b029:2e9:e07c:f290 with SMTP id u13-20020a056a00124db02902e9e07cf290mr7758629pfi.25.1623411510199;
        Fri, 11 Jun 2021 04:38:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623411510; cv=none;
        d=google.com; s=arc-20160816;
        b=HvNpQ7ILro9gB3hlnOyS1PQwtb59NsbMf1ldOF5MHkuqGdW1Kz8ZgZcGoJM5khh9Zc
         l0bTx/bKIYPw5pWGWpISVO1jTLWFlPP69I2r3rh5bHHDRm276sU8Qw3VO4JR7C2ABqwl
         GlfpsH3aKyg2yuDtBU/no9Ex8YtG+CK6Ck45hooOPAyENHzmgWMMGebLaN7pyr91NL5q
         T0u6VtFNHEmQj10+ng3Ui1HhQZUXF2GvtPUqVII0ZlzmSTjtVjmRjzQfBOhLfspfUGnY
         BCXJwoBsXAFPZlubIyFq+lsfn7InN92krhuohyh6GdNhlwJ+BPaYaYhUbWK+cNYCYZPA
         3mMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qhYV4dmRiRSpgYWOGzvvHoyogPprGMAPvN/EL3Ivaw4=;
        b=JaFEVrfnUYhkYdOzSSBzVM0PWT7rovEJcMJdCwEliO+ILrL+CfnK9ESevgicHxgQfA
         zulBlNk5QD4dfa/R/3v21jMZilMXJuJleGeNRCAcJZScRLoN7RgizVY9Lg0/BQAf3KdA
         jNYHa0mEdT3YxA2hWPcxsXQLZYnZH7J32irsbN9I1RIJQAqbuyrlaQBiYTIeaFvhGzT2
         oKZ47+/HeD9J/5Yqb3nS6w1uiLOPukOdK1RUynJL5q8zGIBO9tAVgshZ/xDzyqlzi9I0
         dq3Kp6C62bsspjF7dK5SyBLIeX0AxsdUEVcAImwHifZszNVJa027Mcj5LuAeQcqtbGVl
         M3lQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Jo3ruZFq;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::734 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x734.google.com (mail-qk1-x734.google.com. [2607:f8b0:4864:20::734])
        by gmr-mx.google.com with ESMTPS id ob5si210843pjb.3.2021.06.11.04.38.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Jun 2021 04:38:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::734 as permitted sender) client-ip=2607:f8b0:4864:20::734;
Received: by mail-qk1-x734.google.com with SMTP id q16so4585087qkm.9
        for <kasan-dev@googlegroups.com>; Fri, 11 Jun 2021 04:38:30 -0700 (PDT)
X-Received: by 2002:a37:a2d6:: with SMTP id l205mr3313686qke.326.1623411509230;
 Fri, 11 Jun 2021 04:38:29 -0700 (PDT)
MIME-Version: 1.0
References: <20210529080340.2987212-1-liushixin2@huawei.com>
In-Reply-To: <20210529080340.2987212-1-liushixin2@huawei.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 11 Jun 2021 13:37:52 +0200
Message-ID: <CAG_fn=XjoZAn+h3b9Yh0PgSNCWn6V2dgHoT-PHG_Z2Js6wUkgQ@mail.gmail.com>
Subject: Re: [PATCH -next] riscv: Enable KFENCE for riscv64
To: Liu Shixin <liushixin2@huawei.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, linux-riscv@lists.infradead.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Jo3ruZFq;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::734 as
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

Hi Liu,

On Sat, May 29, 2021 at 9:31 AM Liu Shixin <liushixin2@huawei.com> wrote:
>
> Add architecture specific implementation details for KFENCE and enable
> KFENCE for the riscv64 architecture. In particular, this implements the
> required interface in <asm/kfence.h>.
>
> KFENCE requires that attributes for pages from its memory pool can
> individually be set. Therefore, force the kfence pool to be mapped at
> page granularity.
>
> Testing this patch using the testcases in kfence_test.c and all passed.
>
> Signed-off-by: Liu Shixin <liushixin2@huawei.com>

Looks like you're missing the Acked-by: that Marco gave here:
https://lkml.org/lkml/2021/5/14/588

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXjoZAn%2Bh3b9Yh0PgSNCWn6V2dgHoT-PHG_Z2Js6wUkgQ%40mail.gmail.com.
