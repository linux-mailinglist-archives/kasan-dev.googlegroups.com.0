Return-Path: <kasan-dev+bncBCCMH5WKTMGRBEMTW7EAMGQE4JF7VGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id CA0A8C3F6BF
	for <lists+kasan-dev@lfdr.de>; Fri, 07 Nov 2025 11:27:31 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-341a72e4843sf787581a91.2
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Nov 2025 02:27:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762511250; cv=pass;
        d=google.com; s=arc-20240605;
        b=BnEFh6L5Xp1KuTdo8swhWenfE8m3Hc/0OcLuT56tGGUvcvDOuB4mXkgK1nnyjswdr4
         ntWr1k9YyOLz1W5rqdbSBTMw+k7Dhi8l+79fzG2CC0gW4E49XRmC621sfiX5w9AuqEqS
         EQDFe4Y6mbZLPwrBSyY/JiQhg6GgYoXtkeewoNsQ6Ja64Sf59q4T8F0memw0mDebjvBi
         tP6wKnFy0BuBWRq42n3SfQv4DwNCx1xekBaj9CV1UwgVh80xmpCh9t9EkaRBcdIvBOiT
         bxNi2a+mKdai7HncSp4m7x/gT681/57watpHu7CnrAIgaR74F5TGHj+HGee56nSAJV9M
         bg2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qMonx4IfVkZW3ZIXUYLDS9tjl2UsS/nVIZYJ65Cx1IM=;
        fh=TAMbeI35v1uX2rG3Xr90auJQzJfzBF/Mv9JYleNGGiA=;
        b=Z+m4GMhDoO6zXFM3jwzBExEfIoRd0nm+H8ScKMHYcJHmhgKntavVwr6WQhLwmFyu48
         2zE2KoEAkL8Zyp+MFv6syQLNBgy3VHoU+lk/ZirFA6zqBKURQtjhceo41iKZi9f5V1nh
         KgHHnbiaFRrE53JcNnT2tmCnV9v70J36U/0veMoMZ+L14mrNWP7L0N82Reb2Y5+ofF/e
         inSK/1XMvYADM2R7kS/m3nupuZoNFDu9I8JJgDBAqtMuiRLZ6P6oLicoxzCzGwjPmWCs
         MDAdIbaO+WeBvM7kj/ThFja9HAErxI03i9MZNjutLckedMKW27V2P8wUTI6MQ9OMUHiL
         YyAg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yMUMU5l9;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762511250; x=1763116050; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qMonx4IfVkZW3ZIXUYLDS9tjl2UsS/nVIZYJ65Cx1IM=;
        b=jP7f6Ez5dzQC/OC1+WfK5cowerU+jt6VWw/xZF4L95HNE9LaDVpkqrmWcs7+eQkW7F
         RxeGxxs5SPrB5aXHB4VGWV/KNsjbKheQaMh9yJCiBa1HDFWrjFUVyuB3h6SWV4+NF7O3
         O4/gUxezLZ2gqIEX2c4Yi3yoY2FlOTD8A0U0aioqliSJ7ES44jCld7J/5hOK2ujdNQaK
         /+pAE2tLVn5dnF8CiXLrSIoeCJgc+zynqzRjcH3Ybidqav8dqSeXlBZwb9VSjBcHFsVp
         g1El+IwSD5ejio5/sqWz7nomskJ9Qs/+bnV8UYVS2Up+IoRZ/nCcxjTB2uUkfiIxnLHB
         WXHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762511250; x=1763116050;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=qMonx4IfVkZW3ZIXUYLDS9tjl2UsS/nVIZYJ65Cx1IM=;
        b=YSWNGMQttVDbB6obr5d3016r+2Zv+MJMZ/m9B5VNezr2HHI6HGLPBpqgR6fXwja/0b
         Y8i7flARQ4ZjDSL6zQAhd8qsD5YFdNm1SCGC2Dw9p9aMsjRF5V+MWhlZ++Jza0dU1KKT
         dd6uzpcTME6CT9BMAsHvwt1vCb7kCwzQy7ZCMI6HjRjFeUM4h67R6aYM9GB9qmeoXreL
         pb7DqI92sNRjvax8WTTyV8RhcyzqyIWRiE4W0kR7pKIrDWhsadwUCdr/VvWe24Pv+omq
         qkthVXNGFzJvAyVgch5nru08STQzCF1uqZDAN4TpDpbdT4EO43l18mooyOIFS9bBoGF4
         HGdg==
X-Forwarded-Encrypted: i=2; AJvYcCUlwhmDabXf9BEBf11/GDprTjbRIpP8RZnYJLR/JtY2U5VNCry5tTtj8Q0Q2JBCU9+5u9RwSQ==@lfdr.de
X-Gm-Message-State: AOJu0YwnjugmqsqtKQ6Of9lyatCXTRuKg/682VnK42j/CjuAS3UCIHWW
	cNj/69WLHkXmwoGQWz29WkI+ncYtBQSQ0Vc4UVnNeXtr/CExD1PIMpzC
X-Google-Smtp-Source: AGHT+IHPKO4o4SoASx1n3CeUhOw+k62x5ew/l678OVBLtlaLyU+5OULFg0OkiRmdpEMrtcCd6XcTnw==
X-Received: by 2002:a17:90a:ec8d:b0:32e:a4d:41cb with SMTP id 98e67ed59e1d1-3434c4ea6bdmr2976022a91.1.1762511249792;
        Fri, 07 Nov 2025 02:27:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bVMW5wyDCeUIwhf5oQLd0mROcc047gpBfr9fvMRpcJOg=="
Received: by 2002:a17:90b:3e84:b0:330:4949:15b5 with SMTP id
 98e67ed59e1d1-341cd2d6162ls2517959a91.1.-pod-prod-07-us; Fri, 07 Nov 2025
 02:27:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXi+QYgCtWZQf0niTmRnMvhXd8m3S3UjKaSN243Ox966D5XjyD3Z5p4bPB0LRVb8npf0wh2PPH6MH0=@googlegroups.com
X-Received: by 2002:a17:90b:2590:b0:33e:2934:6e11 with SMTP id 98e67ed59e1d1-3434c4f966fmr3468801a91.11.1762511248101;
        Fri, 07 Nov 2025 02:27:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762511248; cv=none;
        d=google.com; s=arc-20240605;
        b=AfKoNCJu6mUBKdBAjPAH9glFZQGU5+7lBaw3iWJYMUQuJWQGqKx1FfBl4+pMAYze4q
         5dHBAE+a65aLmRVhSBMdigEZPlpBxuzto3RF8emxI5eAF6bnFslCnECKLTQnsB84e9aB
         yA767nvIcUqdCvL0rtzhNy8jGPAIFYKjrOoB9ay9AwkOdocjg95c19swxSAQWaN6oe+1
         HKK9/GUEpIT9Cv80C2Lu5hp5VR+Ul7/L0KWyyksCGPhTsBwKkhvvBo9Z2ZGkr6EQq4xp
         MBRqIzfeupQgMJxzF1eh9VwJkxyKVv9nH4qoPPNnLlbY1WBw0QRZZ8QqEfes9D6e5wC5
         As2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=pLhtIptgftMWRvfp8mRlQOiL9wA5G5qSa8Z4beNB3RU=;
        fh=JEWAfha6St97aXjAaVCQy58nNPHsetQWtVVRZ2dblfU=;
        b=CPZE4BOrSGZOP1ny/G/y/bhAcJksTgXMdVsjQqTwqoNe5IG5/WiXLGcqMkaoGpKw04
         LEX3RivYb5T2VOj9xRcXQ8/VYAm/WaSdiWqVc4Esl548D7SIvOSKCNwjTfF1lsXsI4jw
         A8/HcqW/LKdWh0rlGP6HPcW+pL9bAAhud2m+TwTQ/CZtpcOPXgpV9M7Id8Xv17SalVCH
         t3B38ARRoQamnPJFzLUPVjuPskPm65vClVj3d2EkdLJjRwlTYkRm+/SxPjFhNGfrpGBx
         pM4vIwYL181734itskjYr07BHZK0uipxV5khGLho0MYJWKA2In0ywpfxqaD5DfgnGFZ7
         8A/g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yMUMU5l9;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf36.google.com (mail-qv1-xf36.google.com. [2607:f8b0:4864:20::f36])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-341d0540893si41494a91.2.2025.11.07.02.27.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Nov 2025 02:27:28 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) client-ip=2607:f8b0:4864:20::f36;
Received: by mail-qv1-xf36.google.com with SMTP id 6a1803df08f44-880576ebe38so5669356d6.2
        for <kasan-dev@googlegroups.com>; Fri, 07 Nov 2025 02:27:28 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV7WYbo8966tJnojQt1MVxfbi6vjQ/LPaU/GTGZVhYAlRzH8ZA1gZChcHs7znjupPfQsTQnJ3S8GiE=@googlegroups.com
X-Gm-Gg: ASbGncsSqraER/Ms0HGyG6wJiiGtKCR94TcJtbmoR8sCgp2mLDnElmmE+U9aIV0umnB
	IZzNmTHoMviV6VUEd39TT4CSU5LsPSm++EK8Urj5gYTu6jCyJJiDclpIZDbncGeKw0K6/pYMoh1
	GZSjdKmiCf/UttBY/h1O3Fr63Hu/XOpIxvouCfx+goQm/ekNJcyehpxb9QQ0hjHxV96StXxYbTx
	GflB3kJnXB8hrPf5IfAehj3PQAw07ok95v/mkYBd9hTAHF6KjDGlwIMFQVm44rBl4HYOXBeVJEZ
	e9B28iGBPpCZQsNOIBoMhbvSQA==
X-Received: by 2002:ad4:5e8c:0:b0:87c:fbf:108a with SMTP id
 6a1803df08f44-88167afbb01mr33443336d6.10.1762511246798; Fri, 07 Nov 2025
 02:27:26 -0800 (PST)
MIME-Version: 1.0
References: <20251106160845.1334274-2-aleksei.nikiforov@linux.ibm.com> <20251106160845.1334274-6-aleksei.nikiforov@linux.ibm.com>
In-Reply-To: <20251106160845.1334274-6-aleksei.nikiforov@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 7 Nov 2025 11:26:50 +0100
X-Gm-Features: AWmQ_bnF17f6A18RySh-hO3pa-QL803fyOZqBKR4ZjbBOIO0pB_5mi0dYohMDnE
Message-ID: <CAG_fn=WufanV2DAVusDvGviWqc6woNja-H6WAL5LNgAzeo_uKg@mail.gmail.com>
Subject: Re: [PATCH 2/2] s390/fpu: Fix kmsan in fpu_vstl function
To: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-s390@vger.kernel.org, 
	Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>, 
	Alexander Gordeev <agordeev@linux.ibm.com>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Sven Schnelle <svens@linux.ibm.com>, Thomas Huth <thuth@redhat.com>, 
	Juergen Christ <jchrist@linux.ibm.com>, Ilya Leoshkevich <iii@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=yMUMU5l9;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Thu, Nov 6, 2025 at 5:09=E2=80=AFPM Aleksei Nikiforov
<aleksei.nikiforov@linux.ibm.com> wrote:
>
> clang generates call to __msan_instrument_asm_store with 1 byte as size.
> Manually call kmsan helper to indicate correct amount of bytes written.
>
> If function fpu_vstl is called with argument 'index' > 0,
> it writes at least 2 bytes, but kmsan only marks first byte as written.
>
> This change fixes following kmsan reports:
>
> [   36.563119] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [   36.563594] BUG: KMSAN: uninit-value in virtqueue_add+0x35c6/0x7c70
> [   36.563852]  virtqueue_add+0x35c6/0x7c70
> [   36.564016]  virtqueue_add_outbuf+0xa0/0xb0
> [   36.564266]  start_xmit+0x288c/0x4a20
> [   36.564460]  dev_hard_start_xmit+0x302/0x900
> [   36.564649]  sch_direct_xmit+0x340/0xea0
> [   36.564894]  __dev_queue_xmit+0x2e94/0x59b0
> [   36.565058]  neigh_resolve_output+0x936/0xb40
> [   36.565278]  __neigh_update+0x2f66/0x3a60
> [   36.565499]  neigh_update+0x52/0x60
> [   36.565683]  arp_process+0x1588/0x2de0
> [   36.565916]  NF_HOOK+0x1da/0x240
> [   36.566087]  arp_rcv+0x3e4/0x6e0
> [   36.566306]  __netif_receive_skb_list_core+0x1374/0x15a0
> [   36.566527]  netif_receive_skb_list_internal+0x1116/0x17d0
> [   36.566710]  napi_complete_done+0x376/0x740
> [   36.566918]  virtnet_poll+0x1bae/0x2910
> [   36.567130]  __napi_poll+0xf4/0x830
> [   36.567294]  net_rx_action+0x97c/0x1ed0
> [   36.567556]  handle_softirqs+0x306/0xe10
> [   36.567731]  irq_exit_rcu+0x14c/0x2e0
> [   36.567910]  do_io_irq+0xd4/0x120
> [   36.568139]  io_int_handler+0xc2/0xe8
> [   36.568299]  arch_cpu_idle+0xb0/0xc0
> [   36.568540]  arch_cpu_idle+0x76/0xc0
> [   36.568726]  default_idle_call+0x40/0x70
> [   36.568953]  do_idle+0x1d6/0x390
> [   36.569486]  cpu_startup_entry+0x9a/0xb0
> [   36.569745]  rest_init+0x1ea/0x290
> [   36.570029]  start_kernel+0x95e/0xb90
> [   36.570348]  startup_continue+0x2e/0x40
> [   36.570703]
> [   36.570798] Uninit was created at:
> [   36.571002]  kmem_cache_alloc_node_noprof+0x9e8/0x10e0
> [   36.571261]  kmalloc_reserve+0x12a/0x470
> [   36.571553]  __alloc_skb+0x310/0x860
> [   36.571844]  __ip_append_data+0x483e/0x6a30
> [   36.572170]  ip_append_data+0x11c/0x1e0
> [   36.572477]  raw_sendmsg+0x1c8c/0x2180
> [   36.572818]  inet_sendmsg+0xe6/0x190
> [   36.573142]  __sys_sendto+0x55e/0x8e0
> [   36.573392]  __s390x_sys_socketcall+0x19ae/0x2ba0
> [   36.573571]  __do_syscall+0x12e/0x240
> [   36.573823]  system_call+0x6e/0x90
> [   36.573976]
> [   36.574017] Byte 35 of 98 is uninitialized
> [   36.574082] Memory access of size 98 starts at 0000000007aa0012
> [   36.574218]
> [   36.574325] CPU: 0 UID: 0 PID: 0 Comm: swapper/0 Tainted: G    B      =
      N  6.17.0-dirty #16 NONE
> [   36.574541] Tainted: [B]=3DBAD_PAGE, [N]=3DTEST
> [   36.574617] Hardware name: IBM 3931 A01 703 (KVM/Linux)
> [   36.574755] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D
>
> [   63.532541] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [   63.533639] BUG: KMSAN: uninit-value in virtqueue_add+0x35c6/0x7c70
> [   63.533989]  virtqueue_add+0x35c6/0x7c70
> [   63.534940]  virtqueue_add_outbuf+0xa0/0xb0
> [   63.535861]  start_xmit+0x288c/0x4a20
> [   63.536708]  dev_hard_start_xmit+0x302/0x900
> [   63.537020]  sch_direct_xmit+0x340/0xea0
> [   63.537997]  __dev_queue_xmit+0x2e94/0x59b0
> [   63.538819]  neigh_resolve_output+0x936/0xb40
> [   63.539793]  ip_finish_output2+0x1ee2/0x2200
> [   63.540784]  __ip_finish_output+0x272/0x7a0
> [   63.541765]  ip_finish_output+0x4e/0x5e0
> [   63.542791]  ip_output+0x166/0x410
> [   63.543771]  ip_push_pending_frames+0x1a2/0x470
> [   63.544753]  raw_sendmsg+0x1f06/0x2180
> [   63.545033]  inet_sendmsg+0xe6/0x190
> [   63.546006]  __sys_sendto+0x55e/0x8e0
> [   63.546859]  __s390x_sys_socketcall+0x19ae/0x2ba0
> [   63.547730]  __do_syscall+0x12e/0x240
> [   63.548019]  system_call+0x6e/0x90
> [   63.548989]
> [   63.549779] Uninit was created at:
> [   63.550691]  kmem_cache_alloc_node_noprof+0x9e8/0x10e0
> [   63.550975]  kmalloc_reserve+0x12a/0x470
> [   63.551969]  __alloc_skb+0x310/0x860
> [   63.552949]  __ip_append_data+0x483e/0x6a30
> [   63.553902]  ip_append_data+0x11c/0x1e0
> [   63.554912]  raw_sendmsg+0x1c8c/0x2180
> [   63.556719]  inet_sendmsg+0xe6/0x190
> [   63.557534]  __sys_sendto+0x55e/0x8e0
> [   63.557875]  __s390x_sys_socketcall+0x19ae/0x2ba0
> [   63.558869]  __do_syscall+0x12e/0x240
> [   63.559832]  system_call+0x6e/0x90
> [   63.560780]
> [   63.560972] Byte 35 of 98 is uninitialized
> [   63.561741] Memory access of size 98 starts at 0000000005704312
> [   63.561950]
> [   63.562824] CPU: 3 UID: 0 PID: 192 Comm: ping Tainted: G    B         =
   N  6.17.0-dirty #16 NONE
> [   63.563868] Tainted: [B]=3DBAD_PAGE, [N]=3DTEST
> [   63.564751] Hardware name: IBM 3931 A01 703 (KVM/Linux)
> [   63.564986] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D
>
> Fixes: dcd3e1de9d17 ("s390/checksum: provide csum_partial_copy_nocheck()"=
)
> Reviewed-by: Heiko Carstens <hca@linux.ibm.com>
> Signed-off-by: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
> ---
>  arch/s390/include/asm/fpu-insn.h | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/arch/s390/include/asm/fpu-insn.h b/arch/s390/include/asm/fpu=
-insn.h
> index 135bb89c0a89..151b17e22923 100644
> --- a/arch/s390/include/asm/fpu-insn.h
> +++ b/arch/s390/include/asm/fpu-insn.h
> @@ -393,6 +393,7 @@ static __always_inline void fpu_vstl(u8 v1, u32 index=
, const void *vxr)
>                      : [vxr] "=3DQ" (*(u8 *)vxr)
>                      : [index] "d" (index), [v1] "I" (v1)
>                      : "memory");
> +       instrument_write_after(vxr, size);
>  }
>
>  #else /* CONFIG_CC_HAS_ASM_AOR_FORMAT_FLAGS */
> @@ -409,6 +410,7 @@ static __always_inline void fpu_vstl(u8 v1, u32 index=
, const void *vxr)
>                 : [vxr] "=3DR" (*(u8 *)vxr)
>                 : [index] "d" (index), [v1] "I" (v1)
>                 : "memory", "1");
> +       instrument_write_after(vxr, size);
>  }

Wouldn't it be easier to just call kmsan_unpoison_memory() here directly?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DWufanV2DAVusDvGviWqc6woNja-H6WAL5LNgAzeo_uKg%40mail.gmail.com.
