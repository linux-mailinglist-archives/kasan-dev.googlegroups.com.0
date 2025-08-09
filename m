Return-Path: <kasan-dev+bncBCD5RBOM2UBBBDH23XCAMGQEPNSHFDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 14EB2B1F577
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Aug 2025 18:53:34 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-3e525742ac8sf65144875ab.0
        for <lists+kasan-dev@lfdr.de>; Sat, 09 Aug 2025 09:53:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754758412; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZqYBkwmXqFe1ZP055zb4hpL3gd5Ng9c/d6bT4BD6HDWL1Nq/bzCI2FQLVM8RZR6exI
         8ThCJjBvdZgb4PuFgfRsJKF3cYDnVpNyvJJ89Bws2ewKjAeLANXayJ9AXlP0kzdfkOJV
         cEtVxhfgLb5zL7JZf2Y8EQddKh4zUi1bM3F9RqsnukLMgj4ja4snqiYvdUnKuS3rL5SZ
         Em/q1viKcXqWj+rE1UaUV1MJl+0S1Q0tQIps4EmBopv7ooZwaWuzVgoMQYZJONdLu0fn
         JX0FSYUXOGa7oG7Ll7d3AOEnk3DOFi8973QByRCdOQj5/GTAbTV6tWD+qwAxllT0m9o7
         6vMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature:dkim-signature;
        bh=2G12A8EzddU6ZMOEEWtXGoy0FnVMtVb4jLDtL7qd2+A=;
        fh=3HdTt1aW6U+3Q62HlrFBhFK4FhlOoLhP+MpPRqAvh9w=;
        b=YHrCNLPB87VsQfkRnHqS7bwo77abVU3376IamTRjnYzVeIZk7L+ZxZz+acaEYas98p
         GMVwUh2HWEdXRn51pjtDG6UKvVlRI0YdVqDotwfHYj7zgzvVcvLvbu9wvFbLvQivmhIO
         Y3osn+c46w735Qtb/2PWo0uB9nJfq+4McWft9PT5TfAItpjdnH0c+VJMfe3W8LL/2tRb
         x/dDuzEH2CA0NRdlSPurLEEqxXLRzWCr7A0URkFXPP+PnnsKIGv9kGmCjlbLsf3jEHJ4
         L3wgUFYvdC7hnMSR1zL4agIDPxm5GVjVdOUdtD7HtOb74n/QuIhQesPIakq68Byz0qkX
         Zihw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZsPWdNfI;
       spf=pass (google.com: domain of demiobenour@gmail.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=demiobenour@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754758412; x=1755363212; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2G12A8EzddU6ZMOEEWtXGoy0FnVMtVb4jLDtL7qd2+A=;
        b=xZ7BzI/bQaAdCMvp/G/qAe7MWMYq8EjZca9Zc552NstDSDTA4tyfpUqGxCeZLY7tw+
         eLMRE1xl5CoPg+ZWqvrb+dXiaTkZ8XxLR7wTKj0C594L2lQXrHbTcDMs+YWHUG+XjksK
         quXDUf1CfD04Fbce/ZOIsROk3mSH5NKC9FUyLfOAVokMbqKf35cfMaPMcHt+EMZq0U7C
         /VrUKK1GNjfuJaEBgW1j6j/epleLfmQGUSc2GlYz0+cy6qGlTuYgayKPTOapX8grfV9F
         SvY8JUuhtqNTHimt/OuHspsMn6CxWZWzQG/+FS4PSn2wxu+FB34k00og5bzB2azYxxf6
         l9YQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754758412; x=1755363212; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2G12A8EzddU6ZMOEEWtXGoy0FnVMtVb4jLDtL7qd2+A=;
        b=Jro4BvaxgVXpUiQ24t+F0Wyuyb6ZejaX+n3pI+uY6q4iG1F8xI54SvAGxwkftVk0U5
         fp29KYLyFeVF5u6lpl2UFMETork4Lwv/R4X0BSehBxSxBYEwhlZWX9gB2YrizhAZgyUX
         BkPThxK82gmwLrzgpJoOYP8FZCVHzIywGlEA00HKd5Iio3MbbJm/w4l2yXk34UD9Zstd
         X+SUH5fn+7/JSMuz3KnjPT8hGi3yHtYr8SitJ9s/ci28nCrE5P7LposknPLFpfNt18c3
         9pcUHzEf2yUuccFamdEk9G9ov3ymjvmoozedwrmGmQ1UBD08mN1738ROHBKs48coqeVi
         UdgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754758412; x=1755363212;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2G12A8EzddU6ZMOEEWtXGoy0FnVMtVb4jLDtL7qd2+A=;
        b=p3MUbQRBfFDq78tR2ydyjHsyNCTRz0Dzz057maUQw9QozQGtEWwc7qRv5l6SFZREas
         5Y9S7NTIiwBh74LT8Zge+vKZbo2q2QcPXDerZRaXchCwUZg59FdGM7mUjQPd8wVzx/ln
         C4OmhqyqjqKPeZVMKMMhxt23yegJx0ZK/IuXvrnHzOuDT+4AuvtCwM90tnINJR6sFj6V
         1ZCalVXd6ywxyML6l0Y0jKnHJOm4JEi25MFsYfNsFHr6N0wCwf8DPBdUErkDTZnErW0F
         b+FNatvNOasFnlPv3qlV0F6yCFaN5qSAYu0ELs0xCG1aNrdFEX4P0Wo9Gmc1fQlXJfrZ
         BMpA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXq/bIUA9qRLU/VeMobPx7aBT5xx3oKzlZ3BAllcz7W7/aqdmFJL2a14RN+3uAgaxSiaEXZOg==@lfdr.de
X-Gm-Message-State: AOJu0YyAfQuKPKUTCOU28mUCnvwMc0JFVP3YlvaL8iEZs/7hVkkFX+//
	ilxKzTlPSIrmLRbypa/aie8KiVAFimfK39g8W/7REbxK9rqStcTYV6ow
X-Google-Smtp-Source: AGHT+IGy/Hj1hURQvKtTNdA9W7q1G6A19HehNKl/TvSG/Iei1ZmBvTIAVDXWPURn3FsKoV1ofoKQQA==
X-Received: by 2002:a05:6e02:184e:b0:3e3:ef79:5a8c with SMTP id e9e14a558f8ab-3e533173236mr118563255ab.14.1754758412441;
        Sat, 09 Aug 2025 09:53:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfhZlkiHSwfSuXiGJ2Cj/qTwQwOPr8blw0kc1wi7rscXA==
Received: by 2002:a05:6e02:5e82:b0:3df:1573:75d5 with SMTP id
 e9e14a558f8ab-3e524b2303bls32160415ab.2.-pod-prod-02-us; Sat, 09 Aug 2025
 09:53:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWuByYFvm7IDz4DiYBYCr7cu8FD/bhE9mLB2hOTrGu4Xm8GWikjPHii+v5Qvdrb3up/1FrSMX6vBkg=@googlegroups.com
X-Received: by 2002:a05:6e02:1907:b0:3e3:ef43:f071 with SMTP id e9e14a558f8ab-3e533172cbcmr131427845ab.13.1754758411141;
        Sat, 09 Aug 2025 09:53:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754758411; cv=none;
        d=google.com; s=arc-20240605;
        b=dqdUJwD1EqUlFiFAuZw/dJVMYIinLcvqQqOwmdn/DP4KxhddrDXFrHmtbFpUVYzHL6
         ewwKou3mRejeckywqnc2Iy+jb/0FFHI7ujcqcJGCyLFlQfXulpXoRl0k2Pgg7UC4Ltxd
         1HEDd/Z0dll0Xf0xNTBwLf+npV3lCWMbuW+r2P0l2vcS/HpznB44c1YNzsMan6UmI5Tw
         r0ue53kEqpVhmEtRTr09MEAcwW1rPIjplUiPZ+4/7VYeTrbsup4aWmAgbWHBOM3Cblb4
         8D2iRJzbah4cyTVLLeMCqu8n3MFYnAeNGtNF3dkzK4hsmfeFbOGtBUK5UZzgBC/yvD88
         S9Kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:autocrypt:from:content-language:references:cc:to
         :subject:user-agent:mime-version:date:message-id:dkim-signature;
        bh=b82Zl5v+n85Fe4l4e0mlHahtdka+pmXx7LMxto17f5Q=;
        fh=4nU4RiiYR2co1gL8F2J6R89W9r/xc8uB3zTnXNdT1So=;
        b=C5zw+QrRZJSqdjveNW+QzdVFL5GRSqMqB2bhNpb5SRWH0Ebh3kiVS8OSjYFJZ/tNrr
         hdV+cBkQ4P9LveiVSmBIg1hldaTL27J6fCRSLY6HtSPafzkzb/6c1ASzYmWrAEexyrjd
         cO3vuPceL1eEgEfoLdGbu3idXK78xWGcIRN2KF+1Pg2r1hQ3bn6KvqZm98Q7ywp1XZg9
         VfywpaYmRyS5vUp57ZX1hSmISwD/hk6R/3Lu0XcxeNidVGzbiIoDvttWoL8jndMx4HY7
         fCmEOjwn/RdqrYzvB7U0KvKY/Mr+nKN7Z53YKO4r5aUX+EAraFtowSEiWVCuYYF5j27h
         zY5A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZsPWdNfI;
       spf=pass (google.com: domain of demiobenour@gmail.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=demiobenour@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x733.google.com (mail-qk1-x733.google.com. [2607:f8b0:4864:20::733])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e533cc62a2si2201525ab.5.2025.08.09.09.53.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 09 Aug 2025 09:53:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of demiobenour@gmail.com designates 2607:f8b0:4864:20::733 as permitted sender) client-ip=2607:f8b0:4864:20::733;
Received: by mail-qk1-x733.google.com with SMTP id af79cd13be357-7e6696eb47bso319772185a.3
        for <kasan-dev@googlegroups.com>; Sat, 09 Aug 2025 09:53:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX6Ij0Zxr5H2gwSavQVMPvUPxW03Ib/SEFTc80z272RqhKa5rPYYNv1q8WR/jPcAvO6S9JYaB4sIks=@googlegroups.com
X-Gm-Gg: ASbGncu96ZLMXhXHpzl9RU5PkT5tWSBgyubK1SexifTwZEr8Dzgkil0lE0ukIB1uYH5
	p6pn2B0cbmlYozZxMivEplg9wiZ1hEGwlbXaTfCBQ4TF+HTdhEoYdD2qC8vjvq6Ya4/WfDQ1ul9
	RaXWjsdMpBXCB8Mj/PnYl+Qj5vZ6r2U2iZmLD9LyvHrVaPVVm++yltfTmr9NdCY30F+v4hJxUg5
	xmNb+vWzr1HCWvWgYTz/9ZGY7nNsQ+4NeHlAFrs7nJ0YkMdIsGNNsXEIADfUGeNXci+yCcj/mQk
	JnlkcHkUD8Ag4wxMyOkMH+7zJaYfQHFkHTh4fInqPCeYKEsOuXq43W02LrzOGJxYlI5CrQKiFhs
	C6OmOdFJKrf7w5KqiKJ7zaVltfHjZcsTCr5TPeQ==
X-Received: by 2002:a05:620a:70e7:b0:7e1:ef9c:551b with SMTP id af79cd13be357-7e82c67f4b6mr814292485a.14.1754758410392;
        Sat, 09 Aug 2025 09:53:30 -0700 (PDT)
Received: from [10.138.10.6] ([89.187.178.201])
        by smtp.gmail.com with ESMTPSA id af79cd13be357-7e840d96d78sm64740685a.3.2025.08.09.09.53.26
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 09 Aug 2025 09:53:29 -0700 (PDT)
Message-ID: <6cbaa3a3-694e-4951-abb3-b88e6c9d6638@gmail.com>
Date: Sat, 9 Aug 2025 12:53:09 -0400
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 00/16] dma-mapping: migrate to physical address-based
 API
To: Jason Gunthorpe <jgg@nvidia.com>,
 Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Leon Romanovsky <leon@kernel.org>,
 Abdiel Janulgue <abdiel.janulgue@gmail.com>,
 Alexander Potapenko <glider@google.com>, Alex Gaynor
 <alex.gaynor@gmail.com>, Andrew Morton <akpm@linux-foundation.org>,
 Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
 iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>,
 Jens Axboe <axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>,
 Jonathan Corbet <corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
 kasan-dev@googlegroups.com, Keith Busch <kbusch@kernel.org>,
 linux-block@vger.kernel.org, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-nvme@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
 linux-trace-kernel@vger.kernel.org, Madhavan Srinivasan
 <maddy@linux.ibm.com>, Masami Hiramatsu <mhiramat@kernel.org>,
 Michael Ellerman <mpe@ellerman.id.au>, "Michael S. Tsirkin"
 <mst@redhat.com>, Miguel Ojeda <ojeda@kernel.org>,
 Robin Murphy <robin.murphy@arm.com>, rust-for-linux@vger.kernel.org,
 Sagi Grimberg <sagi@grimberg.me>, Stefano Stabellini
 <sstabellini@kernel.org>, Steven Rostedt <rostedt@goodmis.org>,
 virtualization@lists.linux.dev, Will Deacon <will@kernel.org>,
 xen-devel@lists.xenproject.org
References: <cover.1754292567.git.leon@kernel.org>
 <CGME20250807141938eucas1p2319a0526b25db120b3c9aeb49f69cce1@eucas1p2.samsung.com>
 <20250807141929.GN184255@nvidia.com>
 <a154e058-c0e6-4208-9f52-57cec22eaf7d@samsung.com>
 <20250809133454.GP184255@nvidia.com>
Content-Language: en-US
From: Demi Marie Obenour <demiobenour@gmail.com>
Autocrypt: addr=demiobenour@gmail.com; keydata=
 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
 +MYSfkEjBz0E8CLOcAw7JIwAaeBT
In-Reply-To: <20250809133454.GP184255@nvidia.com>
Content-Type: multipart/signed; micalg=pgp-sha256;
 protocol="application/pgp-signature";
 boundary="------------ANOjCz5i1k7QI0nCYN2dEm0B"
X-Original-Sender: demiobenour@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ZsPWdNfI;       spf=pass
 (google.com: domain of demiobenour@gmail.com designates 2607:f8b0:4864:20::733
 as permitted sender) smtp.mailfrom=demiobenour@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

This is an OpenPGP/MIME signed message (RFC 4880 and 3156)
--------------ANOjCz5i1k7QI0nCYN2dEm0B
Content-Type: multipart/mixed; boundary="------------Tcin0j6gTuXw4zaLOgBCLymL";
 protected-headers="v1"
From: Demi Marie Obenour <demiobenour@gmail.com>
To: Jason Gunthorpe <jgg@nvidia.com>,
 Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Leon Romanovsky <leon@kernel.org>,
 Abdiel Janulgue <abdiel.janulgue@gmail.com>,
 Alexander Potapenko <glider@google.com>, Alex Gaynor
 <alex.gaynor@gmail.com>, Andrew Morton <akpm@linux-foundation.org>,
 Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
 iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>,
 Jens Axboe <axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>,
 Jonathan Corbet <corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
 kasan-dev@googlegroups.com, Keith Busch <kbusch@kernel.org>,
 linux-block@vger.kernel.org, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-nvme@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
 linux-trace-kernel@vger.kernel.org, Madhavan Srinivasan
 <maddy@linux.ibm.com>, Masami Hiramatsu <mhiramat@kernel.org>,
 Michael Ellerman <mpe@ellerman.id.au>, "Michael S. Tsirkin"
 <mst@redhat.com>, Miguel Ojeda <ojeda@kernel.org>,
 Robin Murphy <robin.murphy@arm.com>, rust-for-linux@vger.kernel.org,
 Sagi Grimberg <sagi@grimberg.me>, Stefano Stabellini
 <sstabellini@kernel.org>, Steven Rostedt <rostedt@goodmis.org>,
 virtualization@lists.linux.dev, Will Deacon <will@kernel.org>,
 xen-devel@lists.xenproject.org
Message-ID: <6cbaa3a3-694e-4951-abb3-b88e6c9d6638@gmail.com>
Subject: Re: [PATCH v1 00/16] dma-mapping: migrate to physical address-based
 API
References: <cover.1754292567.git.leon@kernel.org>
 <CGME20250807141938eucas1p2319a0526b25db120b3c9aeb49f69cce1@eucas1p2.samsung.com>
 <20250807141929.GN184255@nvidia.com>
 <a154e058-c0e6-4208-9f52-57cec22eaf7d@samsung.com>
 <20250809133454.GP184255@nvidia.com>
In-Reply-To: <20250809133454.GP184255@nvidia.com>
Autocrypt-Gossip: addr=jgross@suse.com; keydata=
 xsBNBFOMcBYBCACgGjqjoGvbEouQZw/ToiBg9W98AlM2QHV+iNHsEs7kxWhKMjrioyspZKOB
 ycWxw3ie3j9uvg9EOB3aN4xiTv4qbnGiTr3oJhkB1gsb6ToJQZ8uxGq2kaV2KL9650I1SJve
 dYm8Of8Zd621lSmoKOwlNClALZNew72NjJLEzTalU1OdT7/i1TXkH09XSSI8mEQ/ouNcMvIJ
 NwQpd369y9bfIhWUiVXEK7MlRgUG6MvIj6Y3Am/BBLUVbDa4+gmzDC9ezlZkTZG2t14zWPvx
 XP3FAp2pkW0xqG7/377qptDmrk42GlSKN4z76ELnLxussxc7I2hx18NUcbP8+uty4bMxABEB
 AAHNH0p1ZXJnZW4gR3Jvc3MgPGpncm9zc0BzdXNlLmNvbT7CwHkEEwECACMFAlOMcK8CGwMH
 CwkIBwMCAQYVCAIJCgsEFgIDAQIeAQIXgAAKCRCw3p3WKL8TL8eZB/9G0juS/kDY9LhEXseh
 mE9U+iA1VsLhgDqVbsOtZ/S14LRFHczNd/Lqkn7souCSoyWsBs3/wO+OjPvxf7m+Ef+sMtr0
 G5lCWEWa9wa0IXx5HRPW/ScL+e4AVUbL7rurYMfwCzco+7TfjhMEOkC+va5gzi1KrErgNRHH
 kg3PhlnRY0Udyqx++UYkAsN4TQuEhNN32MvN0Np3WlBJOgKcuXpIElmMM5f1BBzJSKBkW0Jc
 Wy3h2Wy912vHKpPV/Xv7ZwVJ27v7KcuZcErtptDevAljxJtE7aJG6WiBzm+v9EswyWxwMCIO
 RoVBYuiocc51872tRGywc03xaQydB+9R7BHPzsBNBFOMcBYBCADLMfoA44MwGOB9YT1V4KCy
 vAfd7E0BTfaAurbG+Olacciz3yd09QOmejFZC6AnoykydyvTFLAWYcSCdISMr88COmmCbJzn
 sHAogjexXiif6ANUUlHpjxlHCCcELmZUzomNDnEOTxZFeWMTFF9Rf2k2F0Tl4E5kmsNGgtSa
 aMO0rNZoOEiD/7UfPP3dfh8JCQ1VtUUsQtT1sxos8Eb/HmriJhnaTZ7Hp3jtgTVkV0ybpgFg
 w6WMaRkrBh17mV0z2ajjmabB7SJxcouSkR0hcpNl4oM74d2/VqoW4BxxxOD1FcNCObCELfIS
 auZx+XT6s+CE7Qi/c44ibBMR7hyjdzWbABEBAAHCwF8EGAECAAkFAlOMcBYCGwwACgkQsN6d
 1ii/Ey9D+Af/WFr3q+bg/8v5tCknCtn92d5lyYTBNt7xgWzDZX8G6/pngzKyWfedArllp0Pn
 fgIXtMNV+3t8Li1Tg843EXkP7+2+CQ98MB8XvvPLYAfW8nNDV85TyVgWlldNcgdv7nn1Sq8g
 HwB2BHdIAkYce3hEoDQXt/mKlgEGsLpzJcnLKimtPXQQy9TxUaLBe9PInPd+Ohix0XOlY+Uk
 QFEx50Ki3rSDl2Zt2tnkNYKUCvTJq7jvOlaPd6d/W0tZqpyy7KVay+K4aMobDsodB3dvEAs6
 ScCnh03dDAFgIq5nsB11j3KPKdVoPlfucX2c7kGNH+LUMbzqV6beIENfNexkOfxHfw==

--------------Tcin0j6gTuXw4zaLOgBCLymL
Content-Type: multipart/mixed; boundary="------------XI3qD7GRJn9UB00QQXegC2mE"

--------------XI3qD7GRJn9UB00QQXegC2mE
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On 8/9/25 09:34, Jason Gunthorpe wrote:
> On Fri, Aug 08, 2025 at 08:51:08PM +0200, Marek Szyprowski wrote:
>> First - basing the=C2=A0API on the phys_addr_t.
>>
>> Page based API had the advantage that it was really hard to abuse it and=
=20
>> call for something that is not 'a normal RAM'.=20
>=20
> This is not true anymore. Today we have ZONE_DEVICE as a struct page
> type with a whole bunch of non-dram sub-types:
>=20
> enum memory_type {
> 	/* 0 is reserved to catch uninitialized type fields */
> 	MEMORY_DEVICE_PRIVATE =3D 1,
> 	MEMORY_DEVICE_COHERENT,
> 	MEMORY_DEVICE_FS_DAX,
> 	MEMORY_DEVICE_GENERIC,
> 	MEMORY_DEVICE_PCI_P2PDMA,
> };
>=20
> Few of which are kmappable/page_to_virtable() in a way that is useful
> for the DMA API.
>=20
> DMA API sort of ignores all of this and relies on the caller to not
> pass in an incorrect struct page. eg we rely on things like the block
> stack to do the right stuff when a MEMORY_DEVICE_PCI_P2PDMA is present
> in a bio_vec.
>=20
> Which is not really fundamentally different from just using
> phys_addr_t in the first place.
>=20
> Sure, this was a stronger argument when this stuff was originally
> written, before ZONE_DEVICE was invented.
>=20
>> I initially though that phys_addr_t based API will somehow simplify
>> arch specific implementation, as some of them indeed rely on
>> phys_addr_t internally, but I missed other things pointed by
>> Robin. Do we have here any alternative?
>=20
> I think it is less of a code simplification, more as a reduction in
> conceptual load. When we can say directly there is no struct page type
> anyhwere in the DMA API layers then we only have to reason about
> kmap/phys_to_virt compatibly.
>=20
> This is also a weaker overall requirement than needing an actual
> struct page which allows optimizing other parts of the kernel. Like we
> aren't forced to create MEMORY_DEVICE_PCI_P2PDMA stuct pages just to
> use the dma api.
>=20
> Again, any place in the kernel we can get rid of struct page the
> smoother the road will be for the MM side struct page restructuring.
>=20
> For example one of the bigger eventual goes here is to make a bio_vec
> store phys_addr_t, not struct page pointers.
>=20
> DMA API is not alone here, we have been de-struct-paging the kernel
> for a long time now:
>=20
> netdev: https://lore.kernel.org/linux-mm/20250609043225.77229-1-byungchul=
@sk.com/
> slab: https://lore.kernel.org/linux-mm/20211201181510.18784-1-vbabka@suse=
.cz/
> iommmu: https://lore.kernel.org/all/0-v4-c8663abbb606+3f7-iommu_pages_jgg=
@nvidia.com/
> page tables: https://lore.kernel.org/linux-mm/20230731170332.69404-1-vish=
al.moola@gmail.com/
> zswap: https://lore.kernel.org/all/20241216150450.1228021-1-42.hyeyoo@gma=
il.com/
>=20
> With a long term goal that struct page only exists for legacy code,
> and is maybe entirely compiled out of modern server kernels.

Why just server kernels?  I suspect client systems actually run
newer kernels than servers do.
--=20
Sincerely,
Demi Marie Obenour (she/her/hers)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6=
cbaa3a3-694e-4951-abb3-b88e6c9d6638%40gmail.com.

--------------XI3qD7GRJn9UB00QQXegC2mE
Content-Type: application/pgp-keys; name="OpenPGP_0xB288B55FFF9C22C1.asc"
Content-Disposition: attachment; filename="OpenPGP_0xB288B55FFF9C22C1.asc"
Content-Description: OpenPGP public key
Content-Transfer-Encoding: quoted-printable

-----BEGIN PGP PUBLIC KEY BLOCK-----

xsFNBFp+A0oBEADffj6anl9/BHhUSxGTICeVl2tob7hPDdhHNgPR4C8xlYt5q49y
B+l2nipdaq+4Gk6FZfqC825TKl7eRpUjMriwle4r3R0ydSIGcy4M6eb0IcxmuPYf
bWpr/si88QKgyGSVZ7GeNW1UnzTdhYHuFlk8dBSmB1fzhEYEk0RcJqg4AKoq6/3/
UorR+FaSuVwT7rqzGrTlscnTDlPWgRzrQ3jssesI7sZLm82E3pJSgaUoCdCOlL7M
MPCJwI8JpPlBedRpe9tfVyfu3euTPLPxwcV3L/cfWPGSL4PofBtB8NUU6QwYiQ9H
zx4xOyn67zW73/G0Q2vPPRst8LBDqlxLjbtx/WLR6h3nBc3eyuZ+q62HS1pJ5EvU
T1vjyJ1ySrqtUXWQ4XlZyoEFUfpJxJoN0A9HCxmHGVckzTRl5FMWo8TCniHynNXs
BtDQbabt7aNEOaAJdE7to0AH3T/Bvwzcp0ZJtBk0EM6YeMLtotUut7h2Bkg1b//r
6bTBswMBXVJ5H44Qf0+eKeUg7whSC9qpYOzzrm7+0r9F5u3qF8ZTx55TJc2g656C
9a1P1MYVysLvkLvS4H+crmxA/i08Tc1h+x9RRvqba4lSzZ6/Tmt60DPM5Sc4R0nS
m9BBff0Nm0bSNRS8InXdO1Aq3362QKX2NOwcL5YaStwODNyZUqF7izjK4QARAQAB
zTxEZW1pIE9iZW5vdXIgKElUTCBFbWFpbCBLZXkpIDxhdGhlbmFAaW52aXNpYmxl
dGhpbmdzbGFiLmNvbT7CwY4EEwEIADgWIQR2h02fEza6IlkHHHGyiLVf/5wiwQUC
X6YJvQIbAwULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRCyiLVf/5wiwWRhD/0Y
R+YYC5Kduv/2LBgQJIygMsFiRHbR4+tWXuTFqgrxxFSlMktZ6gQrQCWe38WnOXkB
oY6n/5lSJdfnuGd2UagZ/9dkaGMUkqt+5WshLFly4BnP7pSsWReKgMP7etRTwn3S
zk1OwFx2lzY1EnnconPLfPBc6rWG2moA6l0WX+3WNR1B1ndqpl2hPSjT2jUCBWDV
rGOUSX7r5f1WgtBeNYnEXPBCUUM51pFGESmfHIXQrqFDA7nBNiIVFDJTmQzuEqIy
Jl67pKNgooij5mKzRhFKHfjLRAH4mmWZlB9UjDStAfFBAoDFHwd1HL5VQCNQdqEc
/9lZDApqWuCPadZN+pGouqLysesIYsNxUhJ7dtWOWHl0vs7/3qkWmWun/2uOJMQh
ra2u8nA9g91FbOobWqjrDd6x3ZJoGQf4zLqjmn/P514gb697788e573WN/MpQ5XI
Fl7aM2d6/GJiq6LC9T2gSUW4rbPBiqOCeiUx7Kd/sVm41p9TOA7fEG4bYddCfDsN
xaQJH6VRK3NOuBUGeL+iQEVF5Xs6Yp+U+jwvv2M5Lel3EqAYo5xXTx4ls0xaxDCu
fudcAh8CMMqx3fguSb7Mi31WlnZpk0fDuWQVNKyDP7lYpwc4nCCGNKCj622ZSocH
AcQmX28L8pJdLYacv9pU3jPy4fHcQYvmTavTqowGnM08RGVtaSBNYXJpZSBPYmVu
b3VyIChsb3ZlciBvZiBjb2RpbmcpIDxkZW1pb2Jlbm91ckBnbWFpbC5jb20+wsF4
BBMBAgAiBQJafgNKAhsDBgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAKCRCyiLVf
/5wiwYa/EACv8a2+MMou9cSCNoZBQaU+fTmyzft9hUE+0d5W2UY1RY3OsjFIzm9R
/4SVccfsqOYLEo+S0vQMIIIqFEq3FCpXXwPzyimotps05VA8U3Bd7yseojFygOgK
sAMOAee2RCaDDOnoJue01dfZMzzHPO/TVdp3OvnpWipfv5G1Xg96rwbhMLE3tg6N
xwAHa31Bv4/Xq8CJOoIWvx6fcmZQpz01/lSvsYn0KrfEbTKkuUf0vM9JrCTCP2oz
VNN5BYzqaq2M4r+jmSyeXLim922VOWqGkUEQ85BSEemqrRS06IU6NtEMsF8EWt/b
hWjk/9GDKTcnpdJHTrMxTspExBiNrvpI2t+YPU5B/dJJAUxvmhFrbSIbdB8umBZs
I3AMYrEmpAbh5x7jEjoskUC7uN3o9vpg1oCLS2ePDLtAtyBtbHnkA4xGD7ar8mem
xpH9lY/i+sC6CyyIUWcUDnnagKyJP0m9ks0GLsTeOCA0bft2XA6rD6aaCnMUsndT
ctrab42CV5XypjmC4U1rPJ8JQJUh1/3P48/8sMH+3krxpJ06KNWNFaUbaMTGiltZ
7x9DngklSYrX0T+2G4kVXNmjaljwkoLahwLla2gUWwBSyofXdqyhQdwZsp01KXNQ
UCyT/Pg+aDcm/E7OMV3d4lf7g/CSxiX2GSEe6BlhSz+Lmd7ZJ3g32M1ARGVtaSBN
YXJpZSBPYmVub3VyIChJVEwgRW1haWwgS2V5KSA8ZGVtaUBpbnZpc2libGV0aGlu
Z3NsYWIuY29tPsLBjgQTAQgAOBYhBHaHTZ8TNroiWQcccbKItV//nCLBBQJgOEV+
AhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJELKItV//nCLBKwoP/1WSnFdv
SAD0g7fD0WlF+oi7ISFT7oqJnchFLOwVHK4Jg0e4hGn1ekWsF3Ha5tFLh4V/7UUu
obYJpTfBAA2CckspYBqLtKGjFxcaqjjpO1I2W/jeNELVtSYuCOZICjdNGw2Hl9yH
KRZiBkqc9u8lQcHDZKq4LIpVJj6ZQV/nxttDX90ax2No1nLLQXFbr5wb465LAPpU
lXwunYDij7xJGye+VUASQh9datye6orZYuJvNo8Tr3mAQxxkfR46LzWgxFCPEAZJ
5P56Nc0IMHdJZj0Uc9+1jxERhOGppp5jlLgYGK7faGB/jTV6LaRQ4Ad+xiqokDWp
mUOZsmA+bMbtPfYjDZBz5mlyHcIRKIFpE1l3Y8F7PhJuzzMUKkJi90CYakCV4x/a
Zs4pzk5E96c2VQx01RIEJ7fzHF7lwFdtfTS4YsLtAbQFsKayqwkGcVv2B1AHeqdo
TMX+cgDvjd1ZganGlWA8Sv9RkNSMchn1hMuTwERTyFTr2dKPnQdA1F480+jUap41
ClXgn227WkCIMrNhQGNyJsnwyzi5wS8rBVRQ3BOTMyvGM07j3axUOYaejEpg7wKi
wTPZGLGH1sz5GljD/916v5+v2xLbOo5606j9dWf5/tAhbPuqrQgWv41wuKDi+dDD
EKkODF7DHes8No+QcHTDyETMn1RYm7t0RKR4zsFNBFp+A0oBEAC9ynZI9LU+uJkM
eEJeJyQ/8VFkCJQPQZEsIGzOTlPnwvVna0AS86n2Z+rK7R/usYs5iJCZ55/JISWd
8xD57ue0eB47bcJvVqGlObI2DEG8TwaW0O0duRhDgzMEL4t1KdRAepIESBEA/iPp
I4gfUbVEIEQuqdqQyO4GAe+MkD0Hy5JH/0qgFmbaSegNTdQg5iqYjRZ3ttiswalq
l1/iSyv1WYeC1OAs+2BLOAT2NEggSiVOtxEfgewsQtCWi8H1SoirakIfo45Hz0tk
/Ad9ZWh2PvOGt97Ka85o4TLJxgJJqGEnqcFUZnJJriwoaRIS8N2C8/nEM53jb1sH
0gYddMU3QxY7dYNLIUrRKQeNkF30dK7V6JRH7pleRlf+wQcNfRAIUrNlatj9Txwi
vQrKnC9aIFFHEy/0mAgtrQShcMRmMgVlRoOA5B8RTulRLCmkafvwuhs6dCxN0GNA
ORIVVFxjx9Vn7OqYPgwiofZ6SbEl0hgPyWBQvE85klFLZLoj7p+joDY1XNQztmfA
rnJ9x+YV4igjWImINAZSlmEcYtd+xy3Li/8oeYDAqrsnrOjb+WvGhCykJk4urBog
2LNtcyCjkTs7F+WeXGUo0NDhbd3Z6AyFfqeF7uJ3D5hlpX2nI9no/ugPrrTVoVZA
grrnNz0iZG2DVx46x913pVKHl5mlYQARAQABwsFfBBgBAgAJBQJafgNKAhsMAAoJ
ELKItV//nCLBwNIP/AiIHE8boIqReFQyaMzxq6lE4YZCZNj65B/nkDOvodSiwfwj
jVVE2V3iEzxMHbgyTCGA67+Bo/d5aQGjgn0TPtsGzelyQHipaUzEyrsceUGWYoKX
YyVWKEfyh0cDfnd9diAm3VeNqchtcMpoehETH8frRHnJdBcjf112PzQSdKC6kqU0
Q196c4Vp5HDOQfNiDnTf7gZSj0BraHOByy9LEDCLhQiCmr+2E0rW4tBtDAn2HkT9
uf32ZGqJCn1O+2uVfFhGu6vPE5qkqrbSE8TG+03H8ecU2q50zgHWPdHMOBvy3Ehz
fAh2VmOSTcRK+tSUe/u3wdLRDPwv/DTzGI36Kgky9MsDC5gpIwNbOJP2G/q1wT1o
Gkw4IXfWv2ufWiXqJ+k7HEi2N1sree7Dy9KBCqb+ca1vFhYPDJfhP75I/VnzHVss
Z/rYZ9+51yDoUABoNdJNSGUYl+Yh9Pw9pE3Kt4EFzUlFZWbE4xKL/NPno+z4J9aW
emLLszcYz/u3XnbOvUSQHSrmfOzX3cV4yfmjM5lewgSstoxGyTx2M8enslgdXhPt
hZlDnTnOT+C+OTsh8+m5tos8HQjaPM01MKBiAqdPgksm1wu2DrrwUi6ChRVTUBcj
6+/9IJ81H2P2gJk3Ls3AVIxIffLoY34E+MYSfkEjBz0E8CLOcAw7JIwAaeBTzsFN
BGbyLVgBEACqClxh50hmBepTSVlan6EBq3OAoxhrAhWZYEwN78k+ENhK68KhqC5R
IsHzlL7QHW1gmfVBQZ63GnWiraM6wOJqFTL4ZWvRslga9u28FJ5XyK860mZLgYhK
9BzoUk4s+dat9jVUbq6LpQ1Ot5I9vrdzo2p1jtQ8h9WCIiFxSYy8s8pZ3hHh5T64
GIj1m/kY7lG3VIdUgoNiREGf/iOMjUFjwwE9ZoJ26j9p7p1U+TkKeF6wgswEB1T3
J8KCAtvmRtqJDq558IU5jhg5fgN+xHB8cgvUWulgK9FIF9oFxcuxtaf/juhHWKMO
RtL0bHfNdXoBdpUDZE+mLBUAxF6KSsRrvx6AQyJs7VjgXJDtQVWvH0PUmTrEswgb
49nNU+dLLZQAZagxqnZ9Dp5l6GqaGZCHERJcLmdY/EmMzSf5YazJ6c0vO8rdW27M
kn73qcWAplQn5mOXaqbfzWkAUPyUXppuRHfrjxTDz3GyJJVOeMmMrTxH4uCaGpOX
Z8tN6829J1roGw4oKDRUQsaBAeEDqizXMPRc+6U9vI5FXzbAsb+8lKW65G7JWHym
YPOGUt2hK4DdTA1PmVo0DxH00eWWeKxqvmGyX+Dhcg+5e191rPsMRGsDlH6KihI6
+3JIuc0y6ngdjcp6aalbuvPIGFrCRx3tnRtNc7He6cBWQoH9RPwluwARAQABwsOs
BBgBCgAgFiEEdodNnxM2uiJZBxxxsoi1X/+cIsEFAmbyLVgCGwICQAkQsoi1X/+c
IsHBdCAEGQEKAB0WIQSilC2pUlbVp66j3+yzNoc6synyUwUCZvItWAAKCRCzNoc6
synyU85gD/0T1QDtPhovkGwoqv4jUbEMMvpeYQf+oWgm/TjWPeLwdjl7AtY0G9Ml
ZoyGniYkoHi37Gnn/ShLT3B5vtyI58ap2+SSa8SnGftdAKRLiWFWCiAEklm9FRk8
N3hwxhmSFF1KR/AIDS4g+HIsZn7YEMubBSgLlZZ9zHl4O4vwuXlREBEW97iL/FSt
VownU2V39t7PtFvGZNk+DJH7eLO3jmNRYB0PL4JOyyda3NH/J92iwrFmjFWWmmWb
/Xz8l9DIs+Z59pRCVTTwbBEZhcUc7rVMCcIYL+q1WxBG2e6lMn15OQJ5WfiE6E0I
sGirAEDnXWx92JNGx5l+mMpdpsWhBZ5iGTtttZesibNkQfd48/eCgFi4cxJUC4PT
UQwfD9AMgzwSTGJrkI5XGy+XqxwOjL8UA0iIrtTpMh49zw46uV6kwFQCgkf32jZM
OLwLTNSzclbnA7GRd8tKwezQ/XqeK3dal2n+cOr+o+Eka7yGmGWNUqFbIe8cjj9T
JeF3mgOCmZOwMI+wIcQYRSf+e5VTMO6TNWH5BI3vqeHSt7HkYuPlHT0pGum88d4a
pWqhulH4rUhEMtirX1hYx8Q4HlUOQqLtxzmwOYWkhl1C+yPObAvUDNiHCLf9w28n
uihgEkzHt9J4VKYulyJM9fe3ENcyU6rpXD7iANQqcr87ogKXFxknZ97uEACvSucc
RbnnAgRqZ7GDzgoBerJ2zrmhLkeREZ08iz1zze1JgyW3HEwdr2UbyAuqvSADCSUU
GN0vtQHsPzWl8onRc7lOPqPDF8OO+UfN9NAfA4wl3QyChD1GXl9rwKQOkbvdlYFV
UFx9u86LNi4ssTmU8p9NtHIGpz1SYMVYNoYy9NU7EVqypGMguDCL7gJt6GUmA0sw
p+YCroXiwL2BJ7RwRqTpgQuFL1gShkA17D5jK4mDPEetq1d8kz9rQYvAR/sTKBsR
ImC3xSfn8zpWoNTTB6lnwyP5Ng1bu6esS7+SpYprFTe7ZqGZF6xhvBPf1Ldi9UAm
U2xPN1/eeWxEa2kusidmFKPmN8lcT4miiAvwGxEnY7Oww9CgZlUB+LP4dl5VPjEt
sFeAhrgxLdpVTjPRRwTd9VQF3/XYl83j5wySIQKIPXgT3sG3ngAhDhC8I8GpM36r
8WJJ3x2yVzyJUbBPO0GBhWE2xPNIfhxVoU4cGGhpFqz7dPKSTRDGq++MrFgKKGpI
ZwT3CPTSSKc7ySndEXWkOYArDIdtyxdE1p5/c3aoz4utzUU7NDHQ+vVIwlnZSMiZ
jek2IJP3SZ+COOIHCVxpUaZ4lnzWT4eDqABhMLpIzw6NmGfg+kLBJhouqz81WITr
EtJuZYM5blWncBOJCoWMnBEcTEo/viU3GgcVRw=3D=3D
=3Dx94R
-----END PGP PUBLIC KEY BLOCK-----

--------------XI3qD7GRJn9UB00QQXegC2mE--

--------------Tcin0j6gTuXw4zaLOgBCLymL--

--------------ANOjCz5i1k7QI0nCYN2dEm0B
Content-Type: application/pgp-signature; name="OpenPGP_signature.asc"
Content-Description: OpenPGP digital signature
Content-Disposition: attachment; filename="OpenPGP_signature.asc"

-----BEGIN PGP SIGNATURE-----

iQIzBAEBCAAdFiEEopQtqVJW1aeuo9/sszaHOrMp8lMFAmiXfP8ACgkQszaHOrMp
8lOWXBAAnJj/H7NOyJp7v2jGgmnhKlYEqtVi6qlmJcJz14v7rr9/EaskUUoYUujH
YJp2/18HGnAPoUbUjxec8OzMRUwx1/a93C3+eCSL1AGwf46p6+oTZqMI8RKa10EN
N8Zn/HcQBQ59AAowJ/XM4UB7bbcG7iqY35SqJ4EiE638m6TkA1I8aFz4xNBS0fuA
5SdjEn7Pdy9MU5J5Isy8K6eDGwHmKOGVLw2wh7PwCOeBX+Nxy6dKs918KO+tQ5OE
V/XHQuejVDUEjzknLlJygVa8riswgiP5sEHUT3ByvPP3gR9pPxw734I5LtLKI6vT
FZHDmcBLkOKsCN7aCP17hef8GziM+krJOh2eMOaMyN6FTvRD3iUluF0TvtEqlnFY
KZ6/eb/T0W5uz++VA9hFaOlq7sLIFUKRZZqdMXPKGVWSfv90jA12s7t12/gah/SY
YKNo6UxWKoDXSZWghJ9AZulG6aXoidf4Z1OIDA/bWR7k0XPYO/ibs9HGKXxfpcC1
ic+vKawKRYsAymyBOrUPYq0tyIO8H6ZGxzSM/U1HvkPnCkcLfb+EhgN0vb10r8+L
vzcnKJc0HQrXPaW9fqEikyWD+KAmpGhUTEJZFlQaiCMk3VYK1cBx1iVi1i+cZY4S
zdJjfggKCJ9cXiQB+4wmUT3TiA+fqC/I9hplAia1eXYCQeDQiNM=
=TrA+
-----END PGP SIGNATURE-----

--------------ANOjCz5i1k7QI0nCYN2dEm0B--
