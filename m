Return-Path: <kasan-dev+bncBCCMH5WKTMGRBUEN63BAMGQE4L3EVGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id DDF0CAEA4A1
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 19:43:49 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-23827190886sf14866385ad.3
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 10:43:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750959825; cv=pass;
        d=google.com; s=arc-20240605;
        b=XdYl2Rddi1jSmzvgWdUhiQQf2ax6KEQfZG8Cqmu+7pfKWVyHkiRgSG7z7FunqjVaBk
         Li9zDkwr6v1LQfDi5MKdDHibs8GDYdTUZCU2qFRbsUxtK36OKT58FcIdxYig/ASwC9i8
         E2yqiFtAuIn6jjflTWS5D3KFsNhwo1CJnBWV+JliTaMDcQ8YrEKWcvBBhzBplhn6ej9I
         /QvujsZmMUfHR4BRNygoHBSrHucWjIXPkm4x6K2ER6nT12GUkqnIMgl/Su7msrOrHrho
         CMJABSfYSmr+N2eq83R8Mq1yUnC1embMskWgV2b03EP3C1VjjrBWMWSIfXCrkcO4PYu9
         P4WA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=N1nS+uIzgzs6/bW8Irs7qWEFZDuxRjCnh4NHQQDux3A=;
        fh=E0JpO+3fCN97xl2+oeHaiK2fQ45VKWpzirVaDzNXkIU=;
        b=ZAdGNovu6ps+xbhLk7m3tUjJjeG4vb1TQRlSrosOVuM0SQbSDFWOXeFINKnUzFa4sX
         LhcYtJQilrMOpq5FD8U79m0PEuAglnaV4WtRgTYzMHN2XdNxvUOeLyG0Jhv0sKx3TZOZ
         Z2aRudtT6a4Y3BbETqN0QvHDU2z6aAs3OTnZOeGhFG9919Sc+SlyJBGLGuL533jlakuF
         A4QiPuZ5luFpmAHKS9RqaKwgk+ifRhchPQ7Tbu9VYKoV66XJiBLE26G0Y1cKz50sG75x
         Nc304gPkxETaFSymiGUf5ILOrxTOF7d/QNMb815BTnCVsEKXF67Su1/rq65x/4Moi/3t
         a+DQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MZw82d2U;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750959825; x=1751564625; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=N1nS+uIzgzs6/bW8Irs7qWEFZDuxRjCnh4NHQQDux3A=;
        b=QGEwop6bL86DbqhamrGFiB0EIpWdrl1iajyuFtkSVsjaj5SqBCLw3kDZdGCifLmlQN
         30OlI39PxvuQk4uFI08aECW2+05VhSsJc/fkw1SMoZ2gvsrq2VzaeeM9bgCw/fI4wdYq
         5DtaJ2/3brXnSvhT9vYUW3A7sX+Gtt+DK1fjXgpIkIaAYe2FMm4nyj7LkV9WTiFJasVL
         nqWiNYkdUWgll7WsJ6QOluNpWgs9g3UoLljgPv9JDUqHUjLGxacHEQniwO/vOjiimF4F
         guRm7rVLhJBpKa5gnXD1inEdzpAZYpvMsIIVslr+wLvKVnMSoHsSL5V6vUf5m2Dp3a7a
         AjmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750959825; x=1751564625;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=N1nS+uIzgzs6/bW8Irs7qWEFZDuxRjCnh4NHQQDux3A=;
        b=vI2ymBpfSObbTVfOmXVbI/3RWp2/BTYSZze27lE/8qAvZufr8cz4Gr8JEi56nYuOQO
         NMu1REt7Y2ePKUPaqFnSBfwgiPJ6DBZoUi+Z6t09IQByYO+DRMvhPvbNIxYpQhJl/cwe
         88TNuWr0IFWY+PGe/UM9c3w48zYEUNIMwhcHnbiIBrjAdSj/x+5ghyOTfzTS+DPS5XmS
         VEJ54m55o9m8PjbUSlIePN3uqXtwU8yej59PHZ2tvFLGGQGxdGf9JRPg4rrBRXwvAjq+
         BcHtJfN3+F1qVArXmD5zRTBPtWuo/3VH8k1n2+oMx7ZfWxUgu/ZsqciJVrJTYlth+r8u
         Mtbg==
X-Forwarded-Encrypted: i=2; AJvYcCW9N9NSEtgeznFUI63jGvrX1Eg2lo8wYZoNq7pF/Qxc+ie16R8FcFx9TrArcUZCOp2HbJeNvw==@lfdr.de
X-Gm-Message-State: AOJu0Yyk7ELO4rMkVX0KxXpHCtJVHY03+mrJBjUB6hv/0tBe0G2NabM9
	4sUVgPsz5tUtj9Xh/R2vlxeV6KdwtVcITlgph/KMlmN54yFjgBg+Lnq3
X-Google-Smtp-Source: AGHT+IFdGl0mNW9HonR73uKgLi5ZjdLCdP98dcVkB2fbJtpJ0SjxDsPxgVulE2xySYcOn8rQqUDZwg==
X-Received: by 2002:a17:902:ea0e:b0:21f:617a:f1b2 with SMTP id d9443c01a7336-23ac46580damr2386695ad.46.1750959825577;
        Thu, 26 Jun 2025 10:43:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeOk1Tm5EWxpYtz1twzF4tTpSGGai1F33ImWGZlPTc8yA==
Received: by 2002:a17:902:e884:b0:234:a78b:7f6b with SMTP id
 d9443c01a7336-238a81c7692ls16130255ad.0.-pod-prod-06-us; Thu, 26 Jun 2025
 10:43:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXxYV81C+C2w6Tw9PSJ9v/CcncBSqb1MFNP8si/5TG19ZmXXrqnPDJ5oZaJ18hlGLa9WaEf+oKo4Z8=@googlegroups.com
X-Received: by 2002:a17:903:3a88:b0:22e:5d9b:2ec3 with SMTP id d9443c01a7336-23ac4606776mr2128685ad.30.1750959823334;
        Thu, 26 Jun 2025 10:43:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750959823; cv=none;
        d=google.com; s=arc-20240605;
        b=UGcKc1iamyXqXIeCbhJN3UoZGOh2F91+T3i/ntocwx3kPkLKNm07TgAsr0gQLpuCMr
         apc/hXofPpi2Mq8FxHqTn83PdmWOoGEglCFUV5m1wqgEdxq3n8ji2yLy/HSf5k/QXVEP
         cIW6aUW+eY2J4XRLaFkvyVSq4JicZeOhvpnKElnmX4VIkxVVsnoa9p75fUkRcXtFPbvG
         yZACM1Rm2Mobp1C2co9O1//vtW6XB1ISCNIT7J9BavnJAnDWuBMj1f0VxjkcyMUUhMBM
         hl+ojIzkepHgiQqv+qONyABYTj+HkPhaOB5kel4vG332pBk4Oydu5fXzzvS+PDMvfpr9
         qvrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=wzwuJqhyKPA6pFtaKqL29WQiBrCe4P+CAFqirUycMO4=;
        fh=FJ4LjdZmJvP1j1axpq0o5oKRpsKUbN2bALVZO1gVJkM=;
        b=gof5r53C6a+8dNdmDqqOKR2XP7/3Ojf8/lqMSs1bCW/QpwVrmpmFYzb3eypgPKTG0I
         qZ4NUq7FPfDVEm3ffPXxbXnBDIaE6gnREa/wglmvr1KBDKvGok/+rn/Sp1kdno4OGIlB
         q7o4nu8zS6w7K6hNU6F1iXcFlDnxFcVt0mDyuu7/3nnN4bBxMb/ryC3xxewUzHKgT2Wn
         O9TZm5rTv1NLWo924c3tbqgieEvejPIToS2gu+7E6vEJLr1uzT1STjhEZ0i4wF/EEl59
         Qd1PpW9h39aq1gVRSAgxJW3kYfaYzYNrGw4GxOTL/xvxxLl28UcAyqzcFlDINQ1s/2/A
         bebA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=MZw82d2U;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2f.google.com (mail-qv1-xf2f.google.com. [2607:f8b0:4864:20::f2f])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-23abe3a9a38si176935ad.7.2025.06.26.10.43.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 10:43:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) client-ip=2607:f8b0:4864:20::f2f;
Received: by mail-qv1-xf2f.google.com with SMTP id 6a1803df08f44-6fafd3cc8f9so21388046d6.3
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 10:43:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW/II0quIotZ/2OCX1cNeodu83FV6lPeC3cF1m6G4q5jarlxUlGHgtlZZuEFTuk5IEdjosvVHVxuR0=@googlegroups.com
X-Gm-Gg: ASbGnctlDph7AWcXrWg71xaPvUtF7VWGd7jy5oflKFFT7NJWi0f6TW4rHhacgIcqwxL
	TUQp/XoZszimQ7LK5k7QYQ6TwL9SnBm7RLthNe0Fk39H3Uyo6rUmc0sAOHbpkjwaOxT2Dj5DLH6
	6WFg+PaHXky+Jc2geQmul+A4M1Ul2KyOFK/N+UBglNuD/mglPPvg0bk4C+w9S9iJeyvOrOoNfW9
	A==
X-Received: by 2002:a05:6214:2aa1:b0:6fb:5f1d:bf8c with SMTP id
 6a1803df08f44-6fffdcff5c9mr6100526d6.11.1750959822639; Thu, 26 Jun 2025
 10:43:42 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1750854543.git.leon@kernel.org> <cabe5b75fe1201baa6ecd209546c1f0913fc02ef.1750854543.git.leon@kernel.org>
In-Reply-To: <cabe5b75fe1201baa6ecd209546c1f0913fc02ef.1750854543.git.leon@kernel.org>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 26 Jun 2025 19:43:06 +0200
X-Gm-Features: Ac12FXyaDZROOxurpvkcs9ZXthsb5DglqUebhn0NTWwPhDYnIEGQjkQ7oqhUUFw
Message-ID: <CAG_fn=XWP-rpV-D2nV-a3wMbzqLn2T-43tyGnoS2AhVGU8oZMw@mail.gmail.com>
Subject: Re: [PATCH 5/8] kmsan: convert kmsan_handle_dma to use physical addresses
To: Leon Romanovsky <leon@kernel.org>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>, Leon Romanovsky <leonro@nvidia.com>, 
	Christoph Hellwig <hch@lst.de>, Jonathan Corbet <corbet@lwn.net>, Madhavan Srinivasan <maddy@linux.ibm.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, 
	Christophe Leroy <christophe.leroy@csgroup.eu>, Robin Murphy <robin.murphy@arm.com>, 
	Joerg Roedel <joro@8bytes.org>, Will Deacon <will@kernel.org>, "Michael S. Tsirkin" <mst@redhat.com>, 
	Jason Wang <jasowang@redhat.com>, Xuan Zhuo <xuanzhuo@linux.alibaba.com>, 
	=?UTF-8?Q?Eugenio_P=C3=A9rez?= <eperezma@redhat.com>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	=?UTF-8?B?SsOpcsO0bWUgR2xpc3Nl?= <jglisse@redhat.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, 
	iommu@lists.linux.dev, virtualization@lists.linux.dev, 
	kasan-dev@googlegroups.com, linux-trace-kernel@vger.kernel.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=MZw82d2U;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as
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

On Wed, Jun 25, 2025 at 3:19=E2=80=AFPM Leon Romanovsky <leon@kernel.org> w=
rote:
>
> From: Leon Romanovsky <leonro@nvidia.com>

Hi Leon,

>
> Convert the KMSAN DMA handling function from page-based to physical
> address-based interface.
>
> The refactoring renames kmsan_handle_dma() parameters from accepting
> (struct page *page, size_t offset, size_t size) to (phys_addr_t phys,
> size_t size).

Could you please elaborate a bit why this is needed? Are you fixing
some particular issue?

> A PFN_VALID check is added to prevent KMSAN operations
> on non-page memory, preventing from non struct page backed address,
>
> As part of this change, support for highmem addresses is implemented
> using kmap_local_page() to handle both lowmem and highmem regions
> properly. All callers throughout the codebase are updated to use the
> new phys_addr_t based interface.

KMSAN only works on 64-bit systems, do we actually have highmem on any of t=
hese?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DXWP-rpV-D2nV-a3wMbzqLn2T-43tyGnoS2AhVGU8oZMw%40mail.gmail.com.
