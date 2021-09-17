Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBNHJSCFAMGQENGZZY3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8471E40F248
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 08:24:53 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id h18-20020ad446f2000000b0037a7b48ba05sf87122786qvw.19
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 23:24:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631859892; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fdzyn55qbJzUmo8QgTOCuFUPAFXiFC7GtpWF4F1L4agOgVfY1wc/5jE5gm850IOeoJ
         sLmvye4prP/4aO0hdHQZUoozqGUef6xqyW8xsV7Eio6QOVSNoMKRFUA63A4XjoIZH7e0
         D9lwm0dwbF3EnGo1zikAIc+3WZEneGxbUSlZkcQaJKLr9nrqFRIXL8Tjn9gBB6oMb58C
         CToKcFy9RrfGojWnXt5z+yF9AjqBQIzPf9xcVWoUYO660v4VtVq5rzrFH3E3Sh8QYPgi
         841UlPrjfFrIPoK4MY2dYLb+Lsz394yO0JVbi++gwD31c0UR7HF2tROtwz/+vDHadRrL
         pihg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=C61mIYzQVXOc98UbbBH1DybfHL70y9UbeqTlGNxQgNs=;
        b=cMKob8xXWOA0KVZWhSCRSAVwScg0S+XG+flg82cf3XjZvRWBhQd7F+13BdKLzyTVkJ
         GhIAhzbRHzUUU4aJhWg/O0Mi23j6uz5Zsn3npWAiRHt3qS/u+IWcaxn2iPHCSfJYO42s
         G1XjOsFPAJrvTq/NTp9f2JxP5Ant/GDeTVA3jL7u05PtICBaK9fp6yQ52qWsMo8d6FZk
         r8HUV6L0N1BelDH2ZKcnwVQkHXEXKWBlanW2H/YJoWgLMVxpWTipxpM4tXPhlZgVGRgl
         SL2jfQZba00U3xcG2KFHKHbEIXWTdbAeZ888WJu2/mF+ny5cXLyztbC6yFEqbQhpxN0c
         puYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=YM10PzX6;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C61mIYzQVXOc98UbbBH1DybfHL70y9UbeqTlGNxQgNs=;
        b=klmEXWTfNuZlnUtZ7jI4RSDdPzmuJNQcMAXml3USkIzL99iQtF2jPkMJGhwHIpdU9z
         F61eXT/J5RxWx7rL+SdjKxxBbwTQwZG9yWW1mjOTP0hDhIwbDVElabQk1o9/tcqGXLft
         vGrBaLMm1f8HoGb21Rfhlr8+J0PG8Vk85Smty/r+NM2ujTH/Zg0D6ccSMpS5SmGmOrRz
         RT1qZLN9hYVh9y7pYo0iBDMrkKFlIKB6jRu1SjtCLTuhRqg7bQ39UdHw6MhbfYKfzmKL
         1JEnBAFXdkbBxeRD8iCl/Srl6242Wgd0rGvb6jHSFOGLU1OchWqq7wgi67SGWvPr9wqO
         bd7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C61mIYzQVXOc98UbbBH1DybfHL70y9UbeqTlGNxQgNs=;
        b=AJYAL25qkvOMeLr4hzDMocf2jO8FiM+Wlqngvpdwd7PLckK5U7FdfykpCNqYt3Rd0D
         NTeRubHZk6mQq05KgpXXG5gzjMF4TJnE447GPaKZboQPEUcTTvA9rJbsAhfw7rb59RpJ
         9xE5khFv/QSUtHNXbQ5vY4gA1NTeLXhEv0Ee8uTSNNw9ygrm4X3KreI4qgLEAzG045Fw
         GuEIUpoH9OdHUoI8r2ClN9mfDshCNbfD3Z9Ax3EnW4fQe4ySUBbP8SylBS9M6YtlgO7s
         VV9KMmWGdAbf5A4zJ32oIU8LfdplX72VRqHfRxhZ6km7STTtogarxhTS+xWPvpmpOYS/
         zoAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531sXLpVKjTZCxpTZ5xNOFjrnpTs5QEXSEPCyMOjUMN1MgIrwRBO
	YodrRnLKu8WQOjXEEWlhYSk=
X-Google-Smtp-Source: ABdhPJxyXdTGJ05su5WPW7EceJ7CDihW1phvlR9QO0o08Zzs55GFghJbnV7JZAofFWm/wT1Cw/huCQ==
X-Received: by 2002:a0c:b286:: with SMTP id r6mr9353040qve.33.1631859892661;
        Thu, 16 Sep 2021 23:24:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:1344:: with SMTP id f4ls5969831qtj.8.gmail; Thu, 16 Sep
 2021 23:24:52 -0700 (PDT)
X-Received: by 2002:ac8:720f:: with SMTP id a15mr9098186qtp.84.1631859892255;
        Thu, 16 Sep 2021 23:24:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631859892; cv=none;
        d=google.com; s=arc-20160816;
        b=hrOpCau/7kA+byTN/SQAHIWujuxm6LbO0bXAJ2rmiWySWOJ6/wHDI7wjaV7AxWWObm
         lpAhUaxO1cVcrpdzWTBFvXb9p2cpChc8OQGITIv7oAVVterNVRWkknvvslkAme+G6kKv
         00z1xt+vFIk0gaG26oyA1cJhqiHz5bXkNzU5TfqpcRBWl3e32Q/FzZ88krN31Rj+fOKI
         8BX77+efcqsOIQkilejNQmOTxgtO65j2hblLowQWLkstvS8C6f3agm91D4eNfUxCpxEo
         XQ45jaZhJ3jh8rXpkQsWwi4FzoCYFudsch2B9EespJvHz3tN63HB93ax7nbymQRRUgBF
         tiKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=HVtimjifHQWpR45qqeeZhyJBBHq0XIb2bwKwTkP6FrA=;
        b=hYGSBMa8ImbpofUc7L+ILMXo4tlV64HfOETKYhP+ktp1GOUeG2792kgKh83HGmx1Kv
         S7mtz57ls/sfbqjCb6AjaFZ525hyqbwRAkGtermQW5oDw8wnuaagrW7ZoDumOQTh0gvN
         ndJoRhfC9EWfZbXys4UeResxrZ/vWn51YlFOOGxKrwjDGyO/3WvepwSGqSJInc0+901f
         PGqkbl5n2FlohscU74mKaD9h1vG6ZKp9my9mQmI3iyAe+7u0pQ5Wzp2wuNyM4AR+xz8m
         MplSaMdT0avi2HTpu54KmXkdoEnwKn+puPkbOU+P/yWH13qwVBSSv2e/ckVcicBcDfoR
         g4Nw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=YM10PzX6;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a21si882192qtm.3.2021.09.16.23.24.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Sep 2021 23:24:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id B596A60F4A;
	Fri, 17 Sep 2021 06:24:50 +0000 (UTC)
Date: Fri, 17 Sep 2021 08:24:48 +0200
From: Greg KH <gregkh@linuxfoundation.org>
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: will@kernel.org, catalin.marinas@arm.com, ryabinin.a.a@gmail.com,
	andreyknvl@gmail.com, dvyukov@google.com,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, elver@google.com, akpm@linux-foundation.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v4 0/3] arm64: support page mapping percpu first chunk
 allocator
Message-ID: <YUQ0sFeM4xqmaNG6@kroah.com>
References: <20210910053354.26721-1-wangkefeng.wang@huawei.com>
 <c06faf6c-3d21-04f2-6855-95c86e96cf5a@huawei.com>
 <YUNlsgZoLG3g4Qup@kroah.com>
 <525cb266-ecfc-284e-d701-4a8b40fe413b@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <525cb266-ecfc-284e-d701-4a8b40fe413b@huawei.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=YM10PzX6;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Fri, Sep 17, 2021 at 09:11:38AM +0800, Kefeng Wang wrote:
>=20
> On 2021/9/16 23:41, Greg KH wrote:
> > On Wed, Sep 15, 2021 at 04:33:09PM +0800, Kefeng Wang wrote:
> > > Hi Greg and Andrew=EF=BC=8C as Catalin saids=EF=BC=8Cthe series touch=
es drivers/ and mm/
> > > but missing
> > >=20
> > > acks from both of you=EF=BC=8Ccould you take a look of this patchset(=
patch1 change
> > > mm/vmalloc.c
> > What patchset?
>=20
> [PATCH v4 1/3] vmalloc: Choose a better start address in
> vm_area_register_early()  <https://lore.kernel.org/linux-arm-kernel/20210=
910053354.26721-2-wangkefeng.wang@huawei.com/>
> [PATCH v4 2/3] arm64: Support page mapping percpu first chunk allocator  =
<https://lore.kernel.org/linux-arm-kernel/20210910053354.26721-3-wangkefeng=
.wang@huawei.com/>
> [PATCH v4 3/3] kasan: arm64: Fix pcpu_page_first_chunk crash with
> KASAN_VMALLOC  <https://lore.kernel.org/linux-arm-kernel/20210910053354.2=
6721-4-wangkefeng.wang@huawei.com/>
> [PATCH v4 0/3] arm64: support page mapping percpu first chunk allocator  =
<https://lore.kernel.org/linux-arm-kernel/c06faf6c-3d21-04f2-6855-95c86e96c=
f5a@huawei.com/>
>=20
> > > and patch2 changes drivers/base/arch_numa.c).
> patch2 =EF=BC=9A
>=20
> [PATCH v4 2/3] arm64: Support page mapping percpu first chunk allocator  =
<https://lore.kernel.org/linux-arm-kernel/20210910053354.26721-3-wangkefeng=
.wang@huawei.com/#r>
>=20
> > that file is not really owned by anyone it seems :(
> >=20
> > Can you provide a link to the real patch please?
>=20
> Yes=EF=BC=8C arch_numa.c is moved into drivers/base to support riscv numa=
, it is
> shared by arm64/riscv,
>=20
> my changes(patch2) only support NEED_PER_CPU_PAGE_FIRST_CHUNK on ARM64.
>=20
> here is the link:
>=20
> https://lore.kernel.org/linux-arm-kernel/20210910053354.26721-1-wangkefen=
g.wang@huawei.com/

Now reviewed.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YUQ0sFeM4xqmaNG6%40kroah.com.
