Return-Path: <kasan-dev+bncBCT4XGV33UIBBNGY73CQMGQE6NAAGVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9096EB4A0A1
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 06:25:26 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id ca18e2360f4ac-88ad82b713csf225358639f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Sep 2025 21:25:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757391925; cv=pass;
        d=google.com; s=arc-20240605;
        b=XFcH+/md0WK+26aqBFbRuAxyse5uNbNs33QJQX5Ba4H1qXo4wBXzuBVnAHoHthQn6k
         jMzGpiO3eHobMU7uBpULI4+T9NBe5rSLXDME+chR2hnnlhs1fn68oGBliMS7YWxQlR5c
         3Gs7j0Y5tqGcwEdWPMtQYtwTcXlF22U4Nea1AmHLltE1dPC8Z18oG0PTk/kIdD6k9hyg
         RFzmcOpcP4t3CAUpqXy37/2bQksbO+vuflaqNq/xuRgnAIERVYmzPtwEphpNboQ8Mv4o
         teAPe6TgJY3c6WzKBgmd4uJoCivm+7sOgYCY/YtqCQGB/fG13lc/9r9zi6OqpUyyJD2w
         0nYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=7H2U9inJj2pTn0rO3/vnzd1FTD0MnK4l4zfTlsI7yTg=;
        fh=prRRmtGgxZ1vPnSwuCRsyF9oCFXvKT/VcCmOM+yaT44=;
        b=UcrMA8dHkGBr11NNxUt7dSC1Q+uqu1GcS7snFpuhEAA8Ihs/J0S7WVmxMoQqY4sicr
         wlZdMyfmXYxu5mY3yns/U+9qfAcod+b9+GuLupmtTk6YREyt4j/C76YK8ENdLp4Q/lsm
         IjUzeNX1IviLc5OLE26+GitZ0T8WFiMCcfTS2G4AX+ljoGgqjZ9JHd2nlJS5aqTEYxsM
         cErptuDG04lyQM/3K9h6SeQ9j6NwWA7UROGTDFcPLbnA7K5MviOAClAVWeer2jux8QPh
         ilWvdKJm26ba0QFwJdWC31Lm7ZUuDjpqlmGFPLAmfSzWSqMMs2Gh/0HxMDPFxQrm0Oaj
         u8aw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=i9pJ18PL;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757391925; x=1757996725; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7H2U9inJj2pTn0rO3/vnzd1FTD0MnK4l4zfTlsI7yTg=;
        b=WDbIHQU11u0v0vZ0PYzfKp2Rpfjpz5MuaV4VpTrdmGtxShNdE1u1W8DX3/rHGBGtEg
         6UoncZqV77rbemAqfRbQ0s6KxLN9w2PYiZPcEiWVjUwn/YKiTglD4Rj/TYIcblnFX7rC
         1si9qxcy09DKHVbeSJAg/4NZLS1/thjTRE1FZ4vBmG20hxWlbgyCm4612k109Gm6LHiN
         iEFzMFl8TLBjud4RplljiW4b08EAoduse4E6u4u8f/Ced3E+kNA7zta0GqxZJ9vjtx1K
         eGT/OYIcqknjWnHudnUVyhoYTo/cMfVdKVh6q9P+XfMlXnv7Gn+F3fOUk54xX7/47bfF
         UHNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757391925; x=1757996725;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7H2U9inJj2pTn0rO3/vnzd1FTD0MnK4l4zfTlsI7yTg=;
        b=Tfs6pDLAbdqM/L8cWExKj8KFEQzzj8jdIMfqqx1E131tEYwAq0ZDwv39f5DN2lJ1g5
         W1K0xdTwWwoave+OTlyB/6b9RH0Dohi0HH9W1XVen+U9Xzlu16/cbeWU7W1846m91oqW
         jU0leMl2XKKTTmMTTSE8sS5pMJjALYip1zqeYkL+wUFD6WliaFVWtwYMi5tEtEshwYp8
         KlnW0sT2+SU4KuQz6B4Xn8GvLeTDLQqIn56T1nRdfYSCgDC34Hh+C6BksD3DPUXw+tS0
         Ua6sVgdCKmb3yIUGzzb0+b7uHVTebI+jBiJZIggtvvg2MsaP3SewLeSLArjV6ONIgSto
         zqVA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVQm3qkfWXM/0hHo1GFbxxt/AVXZh5cVeWAQFpR8X4tc82wB0bpuGoOA1hBNKoDPCc3H86wlg==@lfdr.de
X-Gm-Message-State: AOJu0Yz0vXVw7lwBpXZNgYTcrn0lUREOVgg1akN7U8wE4CV89OejdX7H
	TksqI9M5AMzrx8v3Jubr1CpDkkBVvOtyy5nFb8EBZV2Z4vi1nNBsujti
X-Google-Smtp-Source: AGHT+IFgRByJ6ePkBgCVaB1aGEZ+mCP0fn4k02S63ZBxta93bn+ls+CsbxOFAi15GkrYtwENPiVELg==
X-Received: by 2002:a92:ca46:0:b0:3f2:b471:e617 with SMTP id e9e14a558f8ab-3fd8778175amr147468045ab.25.1757391924846;
        Mon, 08 Sep 2025 21:25:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdyKy9IgZUNYM7omMTFVsfuMqAmH0WqkL09sP1/5lAHQQ==
Received: by 2002:a05:6e02:3305:b0:3f1:4845:aed0 with SMTP id
 e9e14a558f8ab-3fe153c8cfcls22905725ab.1.-pod-prod-07-us; Mon, 08 Sep 2025
 21:25:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVUccXm23ZmZRQgFNdDB7HR4fRyOG+fF8Y1uT6ZuzukygUYlDc2bmOq0zQoeZ+Ldtu9D++5Hjv7HSk=@googlegroups.com
X-Received: by 2002:a05:6e02:3e08:b0:3eb:5862:7cef with SMTP id e9e14a558f8ab-3fd8777fb17mr161997495ab.22.1757391923801;
        Mon, 08 Sep 2025 21:25:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757391923; cv=none;
        d=google.com; s=arc-20240605;
        b=XV6MUs2Eicp6gW2nCPK77IHdaJClOGTwVzbmyoTddjwp4j6xIhfnvIdMYtA5YLO/Fx
         4XQDGEURJp8ZKJr/NKmLz/d2I37HrfLWgcMOOVcL1M057OSNnQ6r1uCI+bL9czRK0k7I
         u0iVzLYEuj6n3RlJllLWXdICmw8K5WYsgGvoY5cYWVhaloFCwemha2IS6qcL7C83OZXA
         rlYjQsUM0x19o6yFxHkFXg1l8mFL3tJ5LgeBV0othqUyVrC8jvivETfsjM53vg+I345N
         NpHpUCOXoKsBD+doGaM0Wwf+doQVVxRplHJeUftEOYL//V2j5J0e8smIvRj7QZGaz6Fg
         HTsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=xDNbPtcfIaumxIyBJ2RGyPKbViivs7UqJ3a/5CcYXNc=;
        fh=TpLX1kBlH3yuhm0hbC1Pp38L+T5jGJdbhfqUHig2DOo=;
        b=QRQDiFX/FnOolyMHQwZV60emjQ9KY/HhsfiuF5lSwAJ29HIrNsp1v22hhxNj55Gyb2
         usnX2NO96nWaLri6dBOmYrZPe1Ozzpg1yuLlMQP9r5Cdh/eMHWzydnHAC+PNim+8+0dc
         ebhFObWBHwWcSkec2PzdsGfETwvsibnBO+ocb+Fy7ccQxHutbpqJa3ZRC0om+AxNPq/N
         saxTPWB4nfC//2DU/yQqr5wJRuC/W8cGtasfCUfj+Aj43tPu3+HP1gayaGRU2+SBH8k5
         GJi/1zCbNNx/ZdDfORpw9as0BypulZSb/cM1nqy+HObN7iqX3/XpdFny4P/XWppS7f3Q
         dsug==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=i9pJ18PL;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-51021bb2ab8si751909173.4.2025.09.08.21.25.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 08 Sep 2025 21:25:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 05467449E2;
	Tue,  9 Sep 2025 04:25:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5F9D2C4CEF4;
	Tue,  9 Sep 2025 04:25:21 +0000 (UTC)
Date: Mon, 8 Sep 2025 21:25:18 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: David Hildenbrand <david@redhat.com>
Cc: Eric Biggers <ebiggers@kernel.org>, linux-kernel@vger.kernel.org,
 Alexander Potapenko <glider@google.com>, Brendan Jackman
 <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>, Dennis Zhou
 <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org, Jason Gunthorpe
 <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>, Johannes Weiner
 <hannes@cmpxchg.org>, John Hubbard <jhubbard@nvidia.com>,
 kasan-dev@googlegroups.com, kvm@vger.kernel.org, "Liam R. Howlett"
 <Liam.Howlett@oracle.com>, Linus Torvalds <torvalds@linux-foundation.org>,
 linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
 linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
 linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
 linux-mmc@vger.kernel.org, linux-mm@kvack.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-scsi@vger.kernel.org, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Marco Elver <elver@google.com>, Marek Szyprowski
 <m.szyprowski@samsung.com>, Michal Hocko <mhocko@suse.com>, Mike Rapoport
 <rppt@kernel.org>, Muchun Song <muchun.song@linux.dev>,
 netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>, Peter Xu
 <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>, Suren
 Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
 virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
 wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH v2 19/37] mm/gup: remove record_subpages()
Message-Id: <20250908212518.77671b31aaad2832c17eab07@linux-foundation.org>
In-Reply-To: <64fe4c61-f9cc-4a5a-9c33-07bd0f089e94@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
	<20250901150359.867252-20-david@redhat.com>
	<5090355d-546a-4d06-99e1-064354d156b5@redhat.com>
	<20250905230006.GA1776@sol>
	<64fe4c61-f9cc-4a5a-9c33-07bd0f089e94@redhat.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=i9pJ18PL;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Sat, 6 Sep 2025 08:57:37 +0200 David Hildenbrand <david@redhat.com> wrote:

> >> @@ -3024,6 +3025,7 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned long addr,
> >>                  return 0;
> >>          }
> >> +       pages += *nr;
> >>          *nr += refs;
> >>          for (; refs; refs--)
> >>                  *(pages++) = page++;
> > 
> > Can this get folded in soon?  This bug is causing crashes in AF_ALG too.
> 
> Andrew immediately dropped the original patch, so it's gone from 
> mm-unstable and should be gone from next soon (today?).

I restored it once you sent out the fix.  It doesn't seem to be in
present -next but it should be there in the next one.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250908212518.77671b31aaad2832c17eab07%40linux-foundation.org.
