Return-Path: <kasan-dev+bncBCKPFB7SXUERBTU6QXCQMGQEOO24OTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D024B2916E
	for <lists+kasan-dev@lfdr.de>; Sun, 17 Aug 2025 05:41:05 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-76e2eb2b837sf2357912b3a.3
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Aug 2025 20:41:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755402063; cv=pass;
        d=google.com; s=arc-20240605;
        b=V1JnWlNKdqvItGQQX5P5Hwt3jF0Vy8V0t7G+AUNujY9IKI3E9WPS4coAykBuDwNPQN
         PC7G6QW5SJC1IjISEvhdyw0rN+RCF12/ehAusmCNlE2KdH9ke5aPoIGlsosyTiPoVIb/
         3yJ83giXcVlTN+BPEcjS+xWrFXLS3S0PHXSNER0PJ/CeJvuX8K38MV94R7wrptz1B9Pw
         XzvNUFAHm2KaojXp+FU1jDcMqXK05wgPrOb0pL47MqzSEW8XY0sb4aOfqfWTf4EKtQ2S
         tGErH6F0jGV/OYsenRt5TrxAizU0daskrNz9Vl+4OUBXK43koQOjBb4rPGodz2pzswrO
         N3vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=M1vn5kWAWP6MrDxf6bRjK0dGRGYEXBIa6U37aEPo+3k=;
        fh=cl9sTeoZbr96/oocqVmy1yIHXcoSM/LcAni8HAYhfz4=;
        b=NYOVXUUvZObUu6OODrxPCxByCj5lwrVzs3fRsysnmIB3TdSiEe1ASrzGQJOvF8ZfLY
         VyvHuoltkq+uMoic0KyBWH8DJjYlCzMD4jQ62/02mZdW+fXF2soZ49MQ76fDPui6sYGV
         WXB4N6NvVFPA9JtmaBFrNR/bMYihzYY/DwMXwXBreKKv5hO1cW/BwE2CWWJE82IgvhOD
         nH3STQsGBYT/scuJTmgZhBGMZe0N1JgevVBNWB08cos4mh+nIVXhxCBbsOA07ZS5UmFd
         Axq0WW29DgqyIp5weM2Xl8c6JJ41UcbotB4Th7q9HzKsbQLDcUWnmocwJgnF9MLs7t0c
         Y+6A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=bNMmqiVn;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755402063; x=1756006863; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=M1vn5kWAWP6MrDxf6bRjK0dGRGYEXBIa6U37aEPo+3k=;
        b=Kvyi3Imvl7qE1b6hjCdfMOSe6CWPaI2dDiOknVNPvCz07NarQMTwvzw7Tk1tYWehqB
         gQrtnb4rzH8h5T34zfork+ovvLSzPrq9RVGzFOJ8Bs9YWQqTO3ZdUaEhAl4oOLY+37Lu
         Ob9Ee4a3BdeGEAoTjsQSG7TcLVvwyXm+ynerokowWIdfYjQNkbBEl5bm/NHGaWexzFcz
         G6FbmrM4wYIUq+gMEKdqYL9yDzbzUaW/umyBMaZtqUetfBSiOJEaCzfRqsHQZvV9VaiV
         P2vFA8Y4OySI/ZX6gEErinAf4UyrkXhXjV6LQFXL7KGYuN1pNL1ffTT58TL4U3PItvy0
         Slcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755402063; x=1756006863;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=M1vn5kWAWP6MrDxf6bRjK0dGRGYEXBIa6U37aEPo+3k=;
        b=vGafO1wUyFhVpENYmGd+GG6R/f8HLEQexv/jycLJQbHIvUShc3KthCCLyZJaip8UYv
         TK2HZxwQfXswZzH2c4fMtq+749ec6NbEarGes4sBhrcumE5ijnKzjB8k1oeUNESp5lgU
         cNfu/brgN1sOKQeiGbZ/rhw49aPEBrcb/LZpNPxepKmpjZnLLvnCJC6ZktTmymCdASPr
         1qv4+mAmCzvr1SL+UogDgGTvmHqThlBm382bbebZjTxMEDYuoiyK7mR8RfovPFt7j3CO
         VSQZhQ9tAIriZ0azQwzaALtmx3aWZUoFchdWtdIPLURkyRjUY56ANZqxQr6AA/vzrK5I
         f/6g==
X-Forwarded-Encrypted: i=2; AJvYcCWNHFtONAbmshHCoxEDqeR0b2YWPpWmg9grnEH4eRe1oOPZs/Rs09ZB6wmwaUxVMMuFEqWz3A==@lfdr.de
X-Gm-Message-State: AOJu0YyqtPbbaxtmKhOCsV/hoOa+sPf3qo8XPqRmc89DYRoQZL48XfoF
	XAFFkm7Z+AmWakG8T/ZJxyyr2ceQNZER1x4g33dScwk2dj0GqIhDi+Jc
X-Google-Smtp-Source: AGHT+IHXbTgw/5VYaqPyYHJdC45ahkW8JaOAi84Qu/8F2yjs+vJFGNLyjIuU2p3hkbhVyaWtDXAurw==
X-Received: by 2002:a05:6a00:92a4:b0:76b:fcac:f2ad with SMTP id d2e1a72fcca58-76e44847105mr10929679b3a.20.1755402062753;
        Sat, 16 Aug 2025 20:41:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZemYckhVNBC78MVoL1bp1G4ljNf6v2IrT0y19BcuPO4xA==
Received: by 2002:a05:6a00:2141:b0:769:ebe1:e48c with SMTP id
 d2e1a72fcca58-76e2ea794f0ls2380374b3a.1.-pod-prod-07-us; Sat, 16 Aug 2025
 20:41:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUNv14KbxuFlD7BPbnwqQjyZLOruNhBLhQDA25NZMtbMqgKV3XWeqpDurTxhXXgYHlTgDanwQN0QjY=@googlegroups.com
X-Received: by 2002:a05:6a20:918c:b0:237:d013:8a78 with SMTP id adf61e73a8af0-240d2f219ffmr11761531637.37.1755402061075;
        Sat, 16 Aug 2025 20:41:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755402061; cv=none;
        d=google.com; s=arc-20240605;
        b=WekiLTu8EgduCF6QwxxQ6aq6atf6IfoOntzIYcCnk17ulG+suxKGkGBbPZFuwlCE0e
         GQD6qjRshWW3fyiD4ATWIAlnTSFy4SHsEVAGhYEMHTzxgrFg+meCCfXXGuCeGBi2VXb2
         BdUoiNVDHYdscLb27rQ0L9m+gQZwRp8ryTwiIc8YiJhSMkl3WgAXlQ7Vt5KvyB4G6X7t
         AaUPrJZJgzWcna7IpRWNiAiYEgNW3iK10XpzJFJHQcLMLPkDNrhqwumkjDu2nHP5Aw72
         HHSvXC2/e8atDL/so7KCEBVwnS3dSeL3XcL/eeMzi1E8ycNKFXPFUaPCszjq0LMuZoPV
         DpWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=3Y0oXgvbJlVAXUapKet03fj1MIE/RRaWOW5OiNzH2oU=;
        fh=gOqAOsSLdoPOBJo0QozQvoXYivyuMTi1+Jbh8fKO3S4=;
        b=K9r/i83ommGYf4rmkp5Di89DK6C5oobUnVT4Y4ymAru8ALhiJk7LbLbK+mKTTosWxd
         OWSFfd+vfyaHpxT+sA2ljG44oVzQAl/+uwt2Wmuocy7f9wVqFjY1KPSNtFhyECKSBzbj
         Ydq8AIs3XeUgPXjDH08z/EN+i0XAKbzEb4TrmDb0asGpE125yZOEzRtUzN32LiDEwmFZ
         3TG7prOsNKBkrGk7NERzPMwLC4vFvlyPC1YvVz34D2bD8a9yKj9p3D4braGmrCQhIi2c
         HQ+3JqoTuQMXaa7sYKb8zvef+ny1MIAsDfaoGyces2rzilOPNkucZJcNTBw89QpWLO4M
         A/qw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=bNMmqiVn;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b472d21ae77si202814a12.0.2025.08.16.20.41.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 16 Aug 2025 20:41:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-80-PkT_4EHSPaqREfWT33cFVQ-1; Sat,
 16 Aug 2025 23:40:55 -0400
X-MC-Unique: PkT_4EHSPaqREfWT33cFVQ-1
X-Mimecast-MFC-AGG-ID: PkT_4EHSPaqREfWT33cFVQ_1755402053
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 544231800340;
	Sun, 17 Aug 2025 03:40:53 +0000 (UTC)
Received: from localhost (unknown [10.72.112.34])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id E5A23180044F;
	Sun, 17 Aug 2025 03:40:50 +0000 (UTC)
Date: Sun, 17 Aug 2025 11:40:46 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	akpm@linux-foundation.org, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org,
	sj@kernel.org, lorenzo.stoakes@oracle.com, elver@google.com,
	snovitoll@gmail.com
Subject: Re: [PATCH v2 00/12] mm/kasan: make kasan=on|off work for all three
 modes
Message-ID: <aKFPPi2sti7+3JZ9@MiWiFi-R3L-srv>
References: <20250812124941.69508-1-bhe@redhat.com>
 <CA+fCnZcAa62uXqnUwxFmDYh1xPqKBOQqOT55kU8iY_pgQg2+NA@mail.gmail.com>
 <CA+fCnZdKy-AQr+L3w=gfaw9EnFvKd0Gz4LtAZciYDP_SiWrL2A@mail.gmail.com>
 <aJxzehJYKez5Q1v2@MiWiFi-R3L-srv>
 <CA+fCnZfv9sbHuRVy8G9QdbKaaeO-Vguf7b2Atc5WXEs+uJx0YQ@mail.gmail.com>
 <aJ2kpEVB4Anyyo/K@MiWiFi-R3L-srv>
 <CA+fCnZcdSDEZvRSxEnogBMCFg1f-PK7PKx0KB_1SA0saY6-21g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZcdSDEZvRSxEnogBMCFg1f-PK7PKx0KB_1SA0saY6-21g@mail.gmail.com>
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=bNMmqiVn;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
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

On 08/16/25 at 06:50am, Andrey Konovalov wrote:
> On Thu, Aug 14, 2025 at 10:56=E2=80=AFAM Baoquan He <bhe@redhat.com> wrot=
e:
> >
> > Ah, I got what you mean. We probably are saying different things.
> >
> > In order to record memory content of a corrupted kernel, we need reserv=
e
> > a memory region during bootup of a normal kernel (usually called 1st
> > kernel) via kernel parameter crashkernel=3DnMB in advance. Then load
> > kernel into the crashkernel memory region, that means the region is not
> > usable for 1st kernel. When 1st kernel collapsed, we stop the 1st kerne=
l
> > cpu/irq and warmly switch to the loaded kernel in the crashkernel memor=
y
> > region (usually called kdump kernel). In kdump kernel, it boots up and
> > enable necessary features to read out the 1st kernel's memory content,
> > we usually use user space tool like makeudmpfile to filter out unwanted
> > memory content.
> >
> > So this patchset intends to disable KASAN to decrease the crashkernel
> > meomry value because crashkernel is not usable for 1st kernel. As for
> > shadow memory of 1st kernel, we need recognize it and filter it away
> > in makedumpfile.
>=20
> Ah, I see, thank you for the explanation!
>=20
> So kdump kernel runs with the amount of RAM specified by crashkernel=3D.
> And KASAN's shadow memory increases RAM usage, which means
> crashkernel=3D needs to be set to a higher value for KASAN kernels. Is
> my understanding of the problem correct?

Yeah, you are quite right.

When I tested it, on x86_64 and arm64, usually I set crashkernel=3D256M
and it's sufficient. However, when KASAN is enabled and generic mode is
taken, I need set crashkernel=3D768M to make vmcore dumping succeed. In
kdump kernel, read_vmcore() uses ioremap to map the old memory of
collapsed kernel for reading out, those vmalloc-ed areas are lazily
freed and cause more shadow memory than what we usually think shadow
memory only costs 1/8 of physical RAM.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
KFPPi2sti7%2B3JZ9%40MiWiFi-R3L-srv.
