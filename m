Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEM3Z2QAMGQERZLSP5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id DA6446BDB17
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 22:43:46 +0100 (CET)
Received: by mail-qt1-x83d.google.com with SMTP id j4-20020ac85f84000000b003d864ebfc20sf1355402qta.14
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Mar 2023 14:43:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679003025; cv=pass;
        d=google.com; s=arc-20160816;
        b=qUWogkTiCgJ3iEnIHcKwPRXe8IgV6z1ZMbWygBQcsk2xOroqffByVnIouYthhlnhzG
         XHqlPoNqPz5ulsr4on/MCpdYauP4ZCYgKROvVnJVLRRoqYoeetnABAd+LXuyyIam+3XM
         2KkqH/eNAKze7CnUYFYvSiiz8yyUEdu/DYvUbvtU9A4ypxD9WoYJI9GrycyGN/dG5g4J
         oGQMO7vjdE82v7eVhvjWEBVsKfmLRQPOr8WEm3KzQMvGF1hB4xm50kjHndOsmxA2N3o7
         yjtDeII2K2G4AuB4lxtFnFz8rfEGMEsK6J9BCm4nhaxBbmTtFlgzFanCHbIkw9DfaBy2
         sSDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=yPci3pF/K1MqrSLr6JDmQOt+qXluy9AQ74I0zULGe7U=;
        b=hSn/iuo2wLyEuglOs2g8nZi4ZqQqZy/iKH5EZjG54Aavm0RfJ8xNep94lPOKJH4qIJ
         ntg7hkQix77VvN6NeurxIVugoVQ0rXiV3w56znNdl7XePItcvjtfbVkSd42RgXM2aaAW
         Bp93F4sK5Q5C+c6r7cb80up42t0M44GM+nSqZYLA3tk2AQEy2AiQokCevhKS6ir421pa
         utDuO88czhHK9TIM2A7mAe2htLu5fxt2mNcvAEDEAITHqyGrxurqZeEe+V6HKyiBJtbw
         UAq4dTIj353nJU5PstLCyCKcJx2ZdoFqGNWsVr+6M10wjWgqzwNf6cB6xWvIRClCqfG2
         xu/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IEfymw96;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679003025;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yPci3pF/K1MqrSLr6JDmQOt+qXluy9AQ74I0zULGe7U=;
        b=PJB2QZeTg41ywX/L+EwKNx08HjpO540mf76qn+lxKClvH6lLSrmU2OF0T2mhuM94jI
         pRIZoswg2A0uOSycGvZpR4OmpXwZoJPXL4G9f8C0QqWpqjeXdtO27Tz6eh+UC+GrPBQv
         b3kG6Os8Hm055YiRL3wP03bTrBGIaFMDm+gwGVqdXA6z2L9wMB2e9xp4Ko22UnOiTPau
         xIBE0fyzkO9GZiHCCOI5ntPa1PQnPL+gHYuRW9dMNVlxtx13YpceES3RiV7SwYq5a6NX
         2O2Id5yLMsSwQvkTy4poackP5dj+l9v1G+XAIEXVeFGoCoKn5l/VnYHrLZenvwuZnEws
         FINQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679003025;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=yPci3pF/K1MqrSLr6JDmQOt+qXluy9AQ74I0zULGe7U=;
        b=XMMn9nggpEgq9slaZ6yQEU4eXAfLxqY0bgnieFrwzrl+B7h94gQ1z9g7O697NdFJZp
         e+VBFd8h2/Rb9NsxFsukPa9mw/CrfQLCZK7FUmnUd+oy7be/35B/CFKo/+92lHCEG5Pe
         hE1Lqrf9XRFIr4sX0y2evauTe2WjiKXjhXIR9F+/Oite4QM6zZwhoGEGqySU0AzLVVxO
         2Xjmehtb+VG9uGTTNHLh2quVRIElV56uK/mx7zYDb/ulrQu2lR5yEqDjhL5RVeB0vwtk
         ghd3U3r9iw/+0xLugPfnT0zmIiFTckooosB0u4aSNHxtzh/GFXOCILVJHftXGVIErEFk
         KoRg==
X-Gm-Message-State: AO0yUKXijTAAiMB0hlAtm3lVuhTEk6pW12DaiL31WDbT1jGOxHhQmV6E
	eUu0qfz0Cmhn6rVtGJoXODk=
X-Google-Smtp-Source: AK7set8PenTr9VgjOr2mu5laCHvJ96MvN4hkj59Rw0KAbO/BbJMNy7u0mvLY19MG+53lpnO7fnjBIw==
X-Received: by 2002:a05:620a:11b0:b0:746:145:5ae with SMTP id c16-20020a05620a11b000b00746014505aemr1818330qkk.2.1679003025548;
        Thu, 16 Mar 2023 14:43:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:905:b0:3c0:184b:29e9 with SMTP id
 bx5-20020a05622a090500b003c0184b29e9ls3194028qtb.4.-pod-prod-gmail; Thu, 16
 Mar 2023 14:43:44 -0700 (PDT)
X-Received: by 2002:a05:622a:1115:b0:3bf:a15e:a898 with SMTP id e21-20020a05622a111500b003bfa15ea898mr8922769qty.18.1679003024852;
        Thu, 16 Mar 2023 14:43:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679003024; cv=none;
        d=google.com; s=arc-20160816;
        b=NDKpAKp8wmrykeh7nqr7+E0FbSUyVxkw7dvC1xWrx/6MaWsGKz3ro3ExQCzilcEMaV
         cnW2mrayZuyWjvOFYOn1yfS1s0fznfZGFd3mNenX/UvJ86jwwO3W9GryPcDAVxaBH3CV
         +Ok/+zQFfXgZtZk6/e0CvCPN4reUwGj2FRC4DbXNuzF/0hyo8RsoLqO/3BB6wgk7Cy2i
         o9PYBXxk7cYg33mweA6W23djo9+5XuWYZ3IBRILHnN+gv8FN5qWtTwR7aMGdcJHwv1f9
         kTJs7J/jCgFM5LX/VC80ng1T0jTPYCQIErqW74er9TGsUb2/+sjWUa2OmVenv+07W+DT
         Dfiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=89DCyBO45qLJ7SI0LJtrAbBk06aDcPzwCqMyiPbaMsg=;
        b=w/Ap7qh8pWLlCp8SJ4Ahuw4GPBo5eBjlLhTrmve9mEVbIXLkTnIrKhkRWRYq0El7Zn
         5cfVmkjZbvDKMXCn5OHhlvwDNvLmWFsRTflfKcAE0rN/mnzB9Wt2Szn+RYPDLAH4niy9
         Zt/FNzxH8B/5RUuZlDS61JMEMZmSXYwOf8xELPj04pudA2guhIqEe1Pd7aBNtQ4GNGZK
         aj6g47KqsmP/MrMDX2gn7U05YpWzef9M6+DNDq9pK4HvBpoFlFAYKK9NWJJw6FNh/PTo
         lSRGaEYPqQiiRYp8OiEkZuAmbBVI/Ej4Pb3mB9px/O3aLhagV2WaXHOKn3veYsJEza8Q
         RGjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IEfymw96;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd32.google.com (mail-io1-xd32.google.com. [2607:f8b0:4864:20::d32])
        by gmr-mx.google.com with ESMTPS id fy9-20020a05622a5a0900b003d5da0c85easi63665qtb.3.2023.03.16.14.43.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Mar 2023 14:43:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d32 as permitted sender) client-ip=2607:f8b0:4864:20::d32;
Received: by mail-io1-xd32.google.com with SMTP id s4so1437490ioj.11
        for <kasan-dev@googlegroups.com>; Thu, 16 Mar 2023 14:43:44 -0700 (PDT)
X-Received: by 2002:a6b:7b48:0:b0:753:1077:e796 with SMTP id
 m8-20020a6b7b48000000b007531077e796mr381563iop.4.1679003024231; Thu, 16 Mar
 2023 14:43:44 -0700 (PDT)
MIME-Version: 1.0
References: <1678979429-25815-1-git-send-email-quic_zhenhuah@quicinc.com>
In-Reply-To: <1678979429-25815-1-git-send-email-quic_zhenhuah@quicinc.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Mar 2023 22:43:02 +0100
Message-ID: <CANpmjNPeyEPOfk_OtxHzZhbJ30W1ik_arW4N1fKW6bpZwB0JCA@mail.gmail.com>
Subject: Re: [PATCH v11] mm,kfence: decouple kfence from page granularity
 mapping judgement
To: Zhenhua Huang <quic_zhenhuah@quicinc.com>
Cc: catalin.marinas@arm.com, will@kernel.org, glider@google.com, 
	dvyukov@google.com, akpm@linux-foundation.org, robin.murphy@arm.com, 
	mark.rutland@arm.com, jianyong.wu@arm.com, james.morse@arm.com, 
	wangkefeng.wang@huawei.com, linux-arm-kernel@lists.infradead.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, quic_pkondeti@quicinc.com, 
	quic_guptap@quicinc.com, quic_tingweiz@quicinc.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=IEfymw96;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d32 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 16 Mar 2023 at 16:10, Zhenhua Huang <quic_zhenhuah@quicinc.com> wrote:
>
> Kfence only needs its pool to be mapped as page granularity, if it is
> inited early. Previous judgement was a bit over protected. From [1], Mark
> suggested to "just map the KFENCE region a page granularity". So I
> decouple it from judgement and do page granularity mapping for kfence
> pool only. Need to be noticed that late init of kfence pool still requires
> page granularity mapping.
>
> Page granularity mapping in theory cost more(2M per 1GB) memory on arm64
> platform. Like what I've tested on QEMU(emulated 1GB RAM) with
> gki_defconfig, also turning off rodata protection:
> Before:
> [root@liebao ]# cat /proc/meminfo
> MemTotal:         999484 kB
> After:
> [root@liebao ]# cat /proc/meminfo
> MemTotal:        1001480 kB
>
> To implement this, also relocate the kfence pool allocation before the
> linear mapping setting up, arm64_kfence_alloc_pool is to allocate phys
> addr, __kfence_pool is to be set after linear mapping set up.
>
> LINK: [1] https://lore.kernel.org/linux-arm-kernel/Y+IsdrvDNILA59UN@FVFF77S0Q05N/
> Suggested-by: Mark Rutland <mark.rutland@arm.com>
> Signed-off-by: Zhenhua Huang <quic_zhenhuah@quicinc.com>
> Reviewed-by: Kefeng Wang <wangkefeng.wang@huawei.com>

Reviewed-by: Marco Elver <elver@google.com>

One question: what happens if the page-granular direct map is
requested either way, is there any downside with this patch? Does it
mean map_mem() just does a little extra work it shouldn't have? (Not
saying that's a problem, just trying to ask you to double-check it's
ok.)

However, please also wait for an arm64 maintainer to have a look. I'm
assuming that because it touches mostly arm64 code, this patch ought
to go through the arm64 tree?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPeyEPOfk_OtxHzZhbJ30W1ik_arW4N1fKW6bpZwB0JCA%40mail.gmail.com.
