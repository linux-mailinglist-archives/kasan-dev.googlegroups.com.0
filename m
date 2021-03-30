Return-Path: <kasan-dev+bncBDW2JDUY5AORBGMNRWBQMGQESBHRTRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3953934ECBF
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 17:41:14 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id r6sf6927692edh.7
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 08:41:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617118874; cv=pass;
        d=google.com; s=arc-20160816;
        b=GUxvcAfmNawmWn0JO549rP6dfnWkuf17/CzdM0KqiMbnJejWmRWUsySo9D/2hhPNRg
         W7WaL6FTZq1x/qunBOOZEGpWD6v/5r4vUTi9OP9zD2MCgrjfkkF4PxeM9+4u1kBmZrKP
         +LC8C0E8df2AH5h1rmDxknnDFOYyvhnT6taqK3Qu7m7/C5djxJ+21dIUTudj2TBXL9uH
         vfmHkmee7TFZwuH+9meQnuuQR1OFH9WXyNkXThvEwNB5yPVfaX4sdBeNg4Xc9vxIg8xi
         yEIUbjxL7TmGXsAiq7w+LJPCk2FRJ3NASc1Tz1uM7cGASDbH/ZIZiyxKXmNS+Ym6FHvr
         WWoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=aWXOKOwIH+8ICcoztgfMAipPdYuAiS0nxqwSn5DMxV0=;
        b=PjwjhmMwP6ahPbtkikXxmfgHvNg95tRFB0G+8BE6PCM7kWbb4kNBJ+cGrgNBa2UJs9
         M4Bzxb7X7xF22HjcDCsRa2XhG7M6dEEnce+N6a7q7RSQg6Fn0HxQLnYUeftghb8J4OZt
         Q2phH8MPT60Uxgadg+8eEMJEuV8aYFxdROQ6Sn+u9irtAaSbyPbEo4cflu4DrpH6MwCY
         UlcnvV0+9eIaiGCnN1F07B7bWxbEchIYmY1jdhAjbeNevKDBEs2DnMP+i/gufmzFdGrD
         2QCFbEpbIIg1azRCPtykRy+VqOMnzdyZl61YiWaoQth0KBOAZHOiFlHtoD0orG2tiy8i
         gckw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=alDstcpg;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aWXOKOwIH+8ICcoztgfMAipPdYuAiS0nxqwSn5DMxV0=;
        b=dH03dVTGioYORGUrIZjmZntBT4Fi/V8wXehcbLCbGSDvZrEC3HgM9i6od9csdSfQlu
         qZyezN4MYS48S62CndpDUq8bEMrk8yOv4cmKKmIltEhutMvucj1UXEJVuqG0O/4J7uY2
         ywOaP7/sAUZnIFfiPX4VaNV8eliQKaFFWstUX5mbJVr7s5s+oriYLyCAQLoNwEJeS1+c
         FzrZV3LTlKEcSgBuCUwrnrKDPpSKGddfiwT0XqrTDAHG+b183a1aP9xz04ToixJx6J1r
         52Bz136UNWFNuHscraQxtdOHL2I8ncWgWxbbK1oObBiDu7aFi5HRYmfFgrHckUmZXo+U
         H+cA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aWXOKOwIH+8ICcoztgfMAipPdYuAiS0nxqwSn5DMxV0=;
        b=OV5j4vsb4iLld/NqRSoQO6kW8MfhMShpXWUcxAUA9WxQkYaat3GE6zQ880cAV+D5xg
         pT+eHnSRM8CNZ9KN6rYuVz+Dm2EoizoeT6MlrNSfTNeFEcuavJ5avDjns+RLiUOll/Vf
         09lkrWnOY2EyEf8tJ8QTg6kNOwJvpfQm5+B/NHtlbNH8jumJXv7CNRoqLpnVXjmTytH7
         5j7jGoBov6sC7Zudt8wrNcw1D6KXLlIaMkg0FQy9QJjLj1ijjYg/gMhoPOCs/pWwU5Ps
         +f6vecVELGodQFUpyjea8VeF4MIrkgE5Yc9qrQ256M+7GtInvcm0qO4eMT5Kl3bOqgNW
         jVIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aWXOKOwIH+8ICcoztgfMAipPdYuAiS0nxqwSn5DMxV0=;
        b=Ljai1a/oyycYwfLZbL0jmXu0IqSqTIX7jQNjbs8PfgKc4zEsM4Md6QYcnEuey0AbPY
         Z4DcwAEMJn8dJRvC7/gSHiiit/ayqrI1ptxA3ON4OmjKEX4L7pxTQf3ofDO+qkCrvWxz
         y4JJXxQCdI16koRdR5y2THpwpWZQ1jgx1lZmwlger3RvZ7y/TpG8Mcv9D8M+vHY4gKz7
         G0mIBRbMlj5T43Znk5RzuKpvDkFhuq/oiAPoWja24plkgiFPIjl9hkvigqjjEBPOXgHn
         FEgTAqC1NcyQkvDNhQpxOOgPbMytuFOvtE9fSEqeDiaomyOvXBBs75xuDanBQj87g9uD
         oTrg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530BSvCiiyUHhYBC1PJ3zKOpsN9V+5vz7t5LQa/8opypaU+C1nEL
	7uGtPLG3A+fcw1lGLEX+B/k=
X-Google-Smtp-Source: ABdhPJzwYI//VKc6FPUeojm8oVR6xygxHiuYCH/34eqi7lnBjgHrNQz4+1vuELxLUKART6OzbHx50g==
X-Received: by 2002:aa7:d484:: with SMTP id b4mr34488746edr.63.1617118874014;
        Tue, 30 Mar 2021 08:41:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c653:: with SMTP id z19ls11274508edr.2.gmail; Tue, 30
 Mar 2021 08:41:13 -0700 (PDT)
X-Received: by 2002:a50:fd15:: with SMTP id i21mr33500164eds.384.1617118873103;
        Tue, 30 Mar 2021 08:41:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617118873; cv=none;
        d=google.com; s=arc-20160816;
        b=HMFi1P7QJQ2cC/qm4xR1Lh9d+BAdgh3jhvRBni2AKuW7vRdZWL1ZbHd2tBbq1/HA3v
         BgEUdxVwcMYuFScRiM0MPZUT+oS5YM06TLLSxvLzvWsrCpni4dSaXkCWbgONE5I1zKzp
         pTOTAx83mCBB22+UiQEepVlKgmH1h5IqIHsAe91BtK2mF2mN1gv3wjE/Bxzb1+WGKVVZ
         tdcTYQ+8NcO/XknmKEDE35BIuUugTMNVU6orkObtq4O2BbIGCugcuLf5oFiGdZo/5kdp
         EasQsjs559APhNdtJJzJFK/08kg+me9h+XmiP25Jz0kvt4wznv5h4QCivICSxOFexzkU
         EKgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DrmbtE2dQXz59+Tv0kxMP5lgZLSi9Ve2ZbONo4ZS6cE=;
        b=qHLwDBXULB+IEJz8RzSNo/r7hRqP4jafN9gm8tQrS4WNwtSuA6cP6Y0dvKgg/vUyOo
         Vb9+PSmUGAFA9LytSL0Dj2KKynfiTnQkLLp2US+j8FE6ukxloAmoioO/2034Wex4lFDM
         hIMFnFNpKA9KaI+8CaRjemcY/xPqUUvB54ckfHbQuYwgbIZO/jbEZgWrdbfBsUvWxpc2
         ZVqIzRWvn2ypaHsIAQi31IVvpYMqjA/S7+kkPEdURjihmhWcGSZwArG2yhDvImJ+AHhH
         Bcn2fkDoJYiyMtvu2Q4UQ61QHq7yTJQVtDIXiZ2UQhdQgfPblX2BGxpWUx5z1WgV2XEo
         IIuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=alDstcpg;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x62f.google.com (mail-ej1-x62f.google.com. [2a00:1450:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id r21si1001447ejo.0.2021.03.30.08.41.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Mar 2021 08:41:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62f as permitted sender) client-ip=2a00:1450:4864:20::62f;
Received: by mail-ej1-x62f.google.com with SMTP id w3so25541281ejc.4
        for <kasan-dev@googlegroups.com>; Tue, 30 Mar 2021 08:41:13 -0700 (PDT)
X-Received: by 2002:a17:907:d1b:: with SMTP id gn27mr33850149ejc.227.1617118872916;
 Tue, 30 Mar 2021 08:41:12 -0700 (PDT)
MIME-Version: 1.0
References: <20210329125449.GA3805@willie-the-truck> <20210330081417.22011-1-lecopzer.chen@mediatek.com>
In-Reply-To: <20210330081417.22011-1-lecopzer.chen@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 30 Mar 2021 17:41:02 +0200
Message-ID: <CA+fCnZdugY3ei_iZ3OLukdgLnGx8b0h-TmbFARXQQWwww3EZmA@mail.gmail.com>
Subject: Re: [PATCH v4 5/5] arm64: Kconfig: select KASAN_VMALLOC if
 KANSAN_GENERIC is enabled
To: Lecopzer Chen <lecopzer.chen@mediatek.com>, Will Deacon <will@kernel.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, gustavoars@kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	LKML <linux-kernel@vger.kernel.org>, linux@roeck-us.net, maz@kernel.org, 
	rppt@kernel.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>, tyhicks@linux.microsoft.com, 
	yj.chiang@mediatek.com, lecopzer@gmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=alDstcpg;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::62f
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

On Tue, Mar 30, 2021 at 10:14 AM Lecopzer Chen
<lecopzer.chen@mediatek.com> wrote:
>
> > Do you know if anybody is working on this? It's really unfortunate that
> > we can't move exclusively to VMAP_STACK just because of SW_TAGS KASAN.
> >
> > That said, what is there to do? As things stand, won't kernel stack
> > addresses end up using KASAN_TAG_KERNEL?
>
> Hi Andrey,
>
> Do you or any KASAN developers have already had any plan for this?

Hi Will and Lecopzer,

We have an issue open to track this [1], but no immediate plans to work on this.

Now that we have GENERIC vmalloc support for arm64, there's a chance
that SW_TAGS vmalloc will just work once allowed via configs. However,
I would expect that we'll still need to at least add some
kasan_reset_tag() annotations here and there.

Thanks!

[1] https://bugzilla.kernel.org/show_bug.cgi?id=211777

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdugY3ei_iZ3OLukdgLnGx8b0h-TmbFARXQQWwww3EZmA%40mail.gmail.com.
