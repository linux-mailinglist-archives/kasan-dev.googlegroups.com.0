Return-Path: <kasan-dev+bncBCKPFB7SXUERBXO22XCAMGQEQIT6KRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3927EB1E0E8
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Aug 2025 05:22:08 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-31ecb3a3d0asf1626444a91.3
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Aug 2025 20:22:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754623326; cv=pass;
        d=google.com; s=arc-20240605;
        b=hIODtZqHGh6zeRfn0+eLEHCTCWPs+EZ/J55qJTTzb3dhmS8lVlCuaru1BnrjBcUm1H
         fzj04COSWDAYH/167rxh4ate6+Lk5tVRKXmPs++yIjBZqOoUf+SlvM+cUvdgJrDExpV5
         ylhQQu51/muqA6CJL5E6lc2wFc5/fXEkeoTZm5E1POKw/hH0jXUjyxVGlnIUSXNcdvKa
         otZDfSb3LaTA7itNjLjkVb1fBvuB4Nz7elM8jIrCztHr6yTigf/HL61Zq1fx/xGTTUA2
         5uhTCHdptuAiRd7DUtHGCqtW0ePaT9MrqQnJLzrupjuKHJkCcHdGK4gLdkTQZDY7Qs/1
         a5OQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=4pEncQbCWEbFgnH4VQuRxAvTHI+BbbOW5hnb2aFeF2I=;
        fh=jtszJSPO+tbF1Dt90gXbZ6Yr6oB15blklM/PfcuIdCU=;
        b=DWLohPV4lSFb6mtCvBiCdkM7YCjqLoO2+H1e+fhlLZMCSu00NAH4+BvdN0KrY+Z97U
         3JkliYdfPmL6+Z9L41KFd6bYDkyjJVe6G1ynGjs6GZ7h1FR4xMOfNax/Tqt+KWPHhG/M
         Hb2DF9EMmz28XNr4briZTax/iYDNlSdmHA4xyQW5tUuDNBgamY6ZBdd8jmxtASsl5D/I
         F8/rczuZyXkhs7KYwf9bRgojut5HDQEf0NvThgUNr1dP+MiTArF3di3lpDDGM4i1D+qm
         KIGG+cTXHdEVtig19uZsGzAtiIcpKMdoMzYDwhMc1+sS8lvMD0PcuZrsbmzm4JbcSgBK
         J16Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=hBeUB1A8;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754623326; x=1755228126; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=4pEncQbCWEbFgnH4VQuRxAvTHI+BbbOW5hnb2aFeF2I=;
        b=lZm51CUvaKX6Gg+ho65gcOTOwnVHvQI9JLvAuC0Av5phZEl7CasbEP7FY035I6o/ys
         TBJ3vTQ2mCZ3BMGFCPyCBRBSbWvzg44jUDrW/kaDK62Biz103Y3p6XyAjMtAxjeoMZkl
         QOdnXeOWOK4/WjgXDnS/XWbYF08p1MqHmKGk4GZdyx5z7fBAKinys26hCzd+ccekYdkB
         Dm+bXNHyPuQSGyU85x0R0LDgqsM7KeMcIh0ArcEsvARt1VJhcV+6/FvKkfRPAk3iB0U4
         VGM2sF1uSimZ+Q+rC80TaAX1+dnCmtoMWpH/eAsgncI7Fuo0TCmgxKG//gPDDPi/DrK8
         j0Cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754623326; x=1755228126;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4pEncQbCWEbFgnH4VQuRxAvTHI+BbbOW5hnb2aFeF2I=;
        b=HL1/wdYXMqlJbHI8LA9PYDzO0A7To0JIuNuNlsQpOfLvkhaloJKNZeKEbhYtxfSZVO
         QyMeUnr4m2E1o4E7BTa9HbzMQfgZ15BFFwShccSLA8FQvhMafE2e9R+B1qEvyvWD1TB6
         iAyfLIelausLvWdoVwRyoOJ+TNzIKYt1JoAUDBdyh92k8bGt84IvOr5Nd1YaMwQwPHvQ
         vjR1WVmPmyMAnidUmp42Yxb7iWspEfX5p8A9orO7L/6gBRqkZFPKSoKUoA1I06FvsnbV
         eZfGIFp4w8GdpVTYGcZIOf2MsFdCR02rE9u7Ic1SL7oFLllTdZ2vKX06T/HiGAYat7Ls
         mueg==
X-Forwarded-Encrypted: i=2; AJvYcCWw5+Z05coZ6LVZpD3ZAM5g5fad7bS49TUAcgsclDV9fVu4B6OsHtUKo9JWPno+G+xmB0WUZA==@lfdr.de
X-Gm-Message-State: AOJu0Yxj27jpDtU+eL45YVYmQBLzkGTjbd4HJPNeq/TWIUx8d7M6aQFH
	bpNIFMx0IreUFR01zc5le363z6FlSarzSIkgqfPO2lq2UKFXJZQULcgs
X-Google-Smtp-Source: AGHT+IGMITZE2zmIaYfHsy9GIblsDzXS44hizq1Dzan2TSQwKMKzfRL76vpR5gqDDIBY6vsa1NbxBA==
X-Received: by 2002:a17:90b:4b0e:b0:311:b413:f5e1 with SMTP id 98e67ed59e1d1-32183e5596emr1602361a91.32.1754623326046;
        Thu, 07 Aug 2025 20:22:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZec5X8iTFH493ukubx80+lSxz81MEJuXaQzwgxQll/O2Q==
Received: by 2002:a17:90b:5291:b0:311:b6ba:c5da with SMTP id
 98e67ed59e1d1-3217506413fls2246692a91.1.-pod-prod-05-us; Thu, 07 Aug 2025
 20:22:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXwqET6ZHd5qX36khKsiWiXAunOAtKxSzHAtYoG61lTOteKRicARIMQGd4OZJaxEldIBD8n9VyLQNw=@googlegroups.com
X-Received: by 2002:a17:90b:3d8a:b0:315:c77b:37d6 with SMTP id 98e67ed59e1d1-32183c47c52mr1785103a91.23.1754623324681;
        Thu, 07 Aug 2025 20:22:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754623324; cv=none;
        d=google.com; s=arc-20240605;
        b=C4/ZFD0TW4831su9VfzPPreSFyGDGSK+BJ4cR0YdOma1jwjE0L0T3FlK00WX/OjuD7
         2PBWpaB2q6PUj9NghJUsaw66FFhc940qYP/mBU7BM0iGk0URt1InirpE09Uet8fpwHRw
         GN6ecKlFuAY8xuTafbNg26UFT+nmK4i6n8KNDzK365jeqG6LrwXctKuWxxh8faA6eRzQ
         ks+UGqYyHO1uYORHlPf8jbuOKV1LUC2Hb/jKwdiWAoK+BAvsgpBTfvrub/lQQC6Z4LYs
         A49UF0F+NusRAaHrYSsAQHqSndcqcBqPVZPxwaPCRJGCbpX+r8pAm+d1jQ2yFYj5dxOu
         vHGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=9v/VfxV4WcSv8mLKBf97De83PUNubQY/hyRrkNkUdjA=;
        fh=8vn/N44CF+h/tiinA3W68jStXGK4/LZZXhv6TbqbA6E=;
        b=BKDjk2J64rqIKkK14O6gXpha4Aes0z6xMreKjPhlKW1NoG8MoZm+Mph9WP9/eOHPQs
         upIBk3TDI9KDhMxV8+P+FDeHqvf2EJ0gjR1VrHNw6zHDzyPv47XTjJn01/vzSDFXN1f8
         P76I8UiREMOLQ1QOtOMhCTFwS7NXBOd0I+EtfVHWQe4hXTLY9pyv4AgnoTXrKxe3TdaG
         miJdR8txNJT6P5/cES9Esr5+qUfPXhWBvEUCHhhJLxJCvapbr7CR3iX2m3QCFwn6U2on
         24+BRznDB9xgDm08FqVqfJmjjiCfz4WIrc1u8Fm6fhAuGQSbzyFQnpvSkhO6IySUN8WV
         DHIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=hBeUB1A8;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3207ec797dfsi1054822a91.3.2025.08.07.20.22.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Aug 2025 20:22:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-477-CQ50kHbEPO-N047aktSPjQ-1; Thu,
 07 Aug 2025 23:22:00 -0400
X-MC-Unique: CQ50kHbEPO-N047aktSPjQ-1
X-Mimecast-MFC-AGG-ID: CQ50kHbEPO-N047aktSPjQ_1754623318
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 8CBDA18004D4;
	Fri,  8 Aug 2025 03:21:57 +0000 (UTC)
Received: from localhost (unknown [10.72.112.126])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 699EB19560AD;
	Fri,  8 Aug 2025 03:21:55 +0000 (UTC)
Date: Fri, 8 Aug 2025 11:21:50 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com,
	andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org
Subject: Re: [PATCH 0/4] mm/kasan: make kasan=on|off work for all three modes
Message-ID: <aJVtTjRUXqWePva0@MiWiFi-R3L-srv>
References: <20250805062333.121553-1-bhe@redhat.com>
 <CANpmjNP-29cuk+MY0w9rvLNizO02yY_ZxP+T0cmCZBi+b5tDTQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNP-29cuk+MY0w9rvLNizO02yY_ZxP+T0cmCZBi+b5tDTQ@mail.gmail.com>
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=hBeUB1A8;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

On 08/06/25 at 09:16am, Marco Elver wrote:
> On Tue, 5 Aug 2025 at 08:23, 'Baoquan He' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > Currently only hw_tags mode of kasan can be enabled or disabled with
> > kernel parameter kasan=on|off for built kernel. For kasan generic and
> > sw_tags mode, there's no way to disable them once kernel is built.
> > This is not convenient sometime, e.g in system kdump is configured.
> > When the 1st kernel has KASAN enabled and crash triggered to switch to
> > kdump kernel, the generic or sw_tags mode will cost much extra memory
> > for kasan shadow while in fact it's meaningless to have kasan in kdump
> > kernel.
> 
> Are you using KASAN generic or SW-tags is production?
> If in a test environment, is the overhead of the kdump kernel really
> unacceptable?

Thanks for checking this.

I don't use KASAN in production environment. But in Redhat, our CI will
run test cases on debug kernel with KASAN enabled by default. Then the
crashkernel setting will be uncertain. E.g usually crashkernel=256M is
enough for most of system. However, KASAN would make the crashkernel
reservation need to reach to 768M on one ampere arm64 system. This is
not the extra 1/8 of system ram as we expected because we have vmalloc
mapping to create shaddow too. In this case, QE or other kernel
developer who is not familiar with KASAN may need spend time to dig out
what's going on here. And they may need adjust crashkernel= value to get
an appropriate one to make system work. This is not good because we
don't need KASAN feature in kdump kernel at all while we need tackle the
unexpected crashkernel= setting.

This can be fixed with a very easy way, a knob to disable kasan in kdump
kernel can perfectly handle it.

> 
> > So this patchset moves the kasan=on|off out of hw_tags scope and into
> > common code to make it visible in generic and sw_tags mode too. Then we
> > can add kasan=off in kdump kernel to reduce the unneeded meomry cost for
> > kasan.
> >
> > Test:
> > =====
> > I only took test on x86_64 for generic mode, and on arm64 for
> > generic, sw_tags and hw_tags mode. All of them works well.
> 
> Does it also work for CONFIG_KASAN_INLINE?

Yes, Andrey said in reply, I did investigation. You can see that
KASAN_INLINE will bloat vmlinux by ~30M. This is not a big problem of
kdump kernel.

CONFIG_KASAN_OUTLINE=y
[root@ampere-mtsnow-altra-08 linux]# ll vmlinux
-rwxr-xr-x. 1 root root 124859016 Aug  6 06:08 vmlinux
[root@ampere-mtsnow-altra-08 linux]# ll /boot/vmlinuz-*
-rwxr-xr-x. 1 root root 15938048 Aug  3 00:15 /boot/vmlinuz-0-rescue-f81ab6a509e444e3857153cfa3fc6497
-rwxr-xr-x. 1 root root 15938048 Jul 23 20:00 /boot/vmlinuz-6.15.8-200.fc42.aarch64
-rwxr-xr-x. 1 root root 20644352 Aug  6 06:11 /boot/vmlinuz-6.16.0+

CONFIG_KASAN_INLINE=y
[root@ampere-mtsnow-altra-08 linux]# ll vmlinux
-rwxr-xr-x. 1 root root 150483592 Aug  6 10:53 vmlinux
[root@ampere-mtsnow-altra-08 linux]# ll /boot/vmlinuz-* 
-rwxr-xr-x. 1 root root  15938048 Aug  3 00:15 /boot/vmlinuz-0-rescue-f81ab6a509e444e3857153cfa3fc6497
-rwxr-xr-x. 1 root root  15938048 Jul 23 20:00 /boot/vmlinuz-6.15.8-200.fc42.aarch64
-rwxr-xr-x. 1 root root  27779584 Aug  6 10:55 /boot/vmlinuz-6.16.0+

> 
> > However when I tested sw_tags on a HPE apollo arm64 machine, it always
> > breaks kernel with a KASAN bug. Even w/o this patchset applied, the bug
> > can always be seen too.
> >
> > "BUG: KASAN: invalid-access in pcpu_alloc_noprof+0x42c/0x9a8"
> >
> > I haven't got root cause of the bug, will report the bug later in
> > another thread.
> > ====
> >
> > Baoquan He (4):
> >   mm/kasan: add conditional checks in functions to return directly if
> >     kasan is disabled
> >   mm/kasan: move kasan= code to common place
> >   mm/kasan: don't initialize kasan if it's disabled
> >   mm/kasan: make kasan=on|off take effect for all three modes
> >
> >  arch/arm/mm/kasan_init.c               |  6 +++++
> >  arch/arm64/mm/kasan_init.c             |  7 ++++++
> >  arch/loongarch/mm/kasan_init.c         |  5 ++++
> >  arch/powerpc/mm/kasan/init_32.c        |  8 +++++-
> >  arch/powerpc/mm/kasan/init_book3e_64.c |  6 +++++
> >  arch/powerpc/mm/kasan/init_book3s_64.c |  6 +++++
> >  arch/riscv/mm/kasan_init.c             |  6 +++++
> >  arch/um/kernel/mem.c                   |  6 +++++
> >  arch/x86/mm/kasan_init_64.c            |  6 +++++
> >  arch/xtensa/mm/kasan_init.c            |  6 +++++
> >  include/linux/kasan-enabled.h          | 11 ++------
> >  mm/kasan/common.c                      | 27 ++++++++++++++++++++
> >  mm/kasan/generic.c                     | 20 +++++++++++++--
> >  mm/kasan/hw_tags.c                     | 35 ++------------------------
> >  mm/kasan/init.c                        |  6 +++++
> >  mm/kasan/quarantine.c                  |  3 +++
> >  mm/kasan/shadow.c                      | 23 ++++++++++++++++-
> >  mm/kasan/sw_tags.c                     |  9 +++++++
> >  18 files changed, 150 insertions(+), 46 deletions(-)
> >
> > --
> > 2.41.0
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250805062333.121553-1-bhe%40redhat.com.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aJVtTjRUXqWePva0%40MiWiFi-R3L-srv.
