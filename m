Return-Path: <kasan-dev+bncBD22BAF5REGBBL4YX3CQMGQEBQHMMFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id DF832B38EC6
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:52:32 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-70a9f562165sf11192666d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:52:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756335152; cv=pass;
        d=google.com; s=arc-20240605;
        b=WV5iy1Tn0eyqpSr3oNYWNv7AgFsNX5WbwoHspi8piCrf83XHbUAQeoLbzS3stXIvuw
         9YPJfooY95ybdxRIzOiahCLo3V3zS3GTNi816cHqOgBM2P1KusfI87ObwPJB0xtkAnOu
         yuSLbd8kBZlRpJQJA55t4A7dZDvD4KaB9qwYWkAmRjLtyTos9DKFHdQqKrRieS8JJkNo
         NaKLSHMjL0QKLi1w3IR58jeOw6BVA2wH+9/KX4f5LFpNiQG/tTw4VM/dDYZTjIM9LgP6
         Nl9Ykme4lRvSubeH0qDaAZNz0PCArp6vqRlYr/VMOi8fWdBui+v6ObKZkSAanC53qZ6d
         G7+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=+tAluJ7PXciytUX3yZqi/kTLLuFRwFCZJHb3tc67TPI=;
        fh=QFljUinXppCBDwY3UQ1abtWNREXLxGer5lv42/sVflo=;
        b=QTN6nV66AzCmHi25t3c0qAyuJwN7ng73yA0DRPCfm5VPc3sowbAWdDK6j76CckwV1E
         wgdsW4MPsq4k0YPceak9lWzAY9pVc1uG+uenxtF4vSDvfvce5pTQJxlcttj5XOhbRZdz
         GaFC3yVWsqyxR4lWjfHws/JUhyddUCjMkXqspy/gQq0nd5fk0ybi5hoQlJEhEIu4jVPg
         zPUKJJceukgR1hUVDB1FHWiohkWc4FYOmWrNOLITwJR6bWmCf+mnS+3rxxnNl7/C4MIu
         fu41zmXwM42y1AsuJelmDRixoFcOAO3cB/QsXfMGT3bSnUJGj5xyUbPBYFB+mH6yLe8L
         ZWBQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ZqUYD5aQ;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.12 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756335151; x=1756939951; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+tAluJ7PXciytUX3yZqi/kTLLuFRwFCZJHb3tc67TPI=;
        b=WRx0vc0VWzqup5tTZWP/zo/33RUSw2Ed542KskvMfPIt+IBtLLb2t3N1TXnTnwDfnV
         r22jR70BvUA3hYmu3T5dIhRv+Fjs5eIgEawWRWuZbNYmeaa4mTILuLBx8yrKuJdcwKAc
         gonmdvdF0VPVgNTaeWh/qDb9HngW5DbBcFdpliWycH72ckKf4l9SNaKwJ+3df1J0bn1A
         frDj1yj9tmdA5G27P2cfH2TsYvP4G+idKu0KjG4O/p4Sw0KT/VKTLsnUT/3JNgHn2Nz9
         p3arJG1aMH2EPl7JgRRoKe762aFGc6C2HS406dyw2ziMIVLamx7qr7bBzO0MNHaWoDsh
         vDDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756335151; x=1756939951;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+tAluJ7PXciytUX3yZqi/kTLLuFRwFCZJHb3tc67TPI=;
        b=s+uylv80zZQgwQeQrp3277kHzSVKDKeWnVwil31Pk8WdAGzici7kgpfPIUyNS+uu5N
         samEg8gBcVdnYuX5Sw4knbY8q2teTsHTIgDLi+IBbEKMfCOAs/HNWo42kijzHWccPNzb
         8C05Kx0wmR0pyjLM4NU663bX3VlG1ER5eANZJo3e9gkaoRUl0UXMcxuTxOZaPwx6Oymt
         PpF4rnAKSfuG2uZM0BAUtIPjdTQYqBJa+czO6cfcErVm8sC2C2/Cwf/OnIthzSlmzDX8
         lRBWktSGzFTA5EBmgJcD14Wh475XY26koyQ+0sjB7Vam8KXlcCz5HtdIfkdJQcb/Otut
         K/IQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUymkh7NGOfRdXWmcAgAQuRVJd8bdn9mX6SquLZEqlXAXzs0St5e1tuHdP1lh0inDkJl5/PfQ==@lfdr.de
X-Gm-Message-State: AOJu0YyU60z8O5nfGBlAXqBSp8w+RHSyXA7AuNK4E9aXzvTf53ADYpUj
	8VkXssi7kuxdUnX2D/rpv+jbHJQPTqDn+TR5K8T8s1vrtKREke1m2QIp
X-Google-Smtp-Source: AGHT+IGgmfFpJtjP5cSH7zgR4pCpwtwt2yLSG1rIlhHLpmLP4hNZ19cAmELIPAsc+DqP5iWGrVRyaw==
X-Received: by 2002:a05:6214:21c2:b0:70d:e3dc:331d with SMTP id 6a1803df08f44-70de3dc375fmr49143586d6.58.1756335151600;
        Wed, 27 Aug 2025 15:52:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfo/LhH+H5t+7d7QtUYM5MDwaC2HIWAF/k6nOpSPrFFnw==
Received: by 2002:a05:6214:3016:b0:709:f373:9f9e with SMTP id
 6a1803df08f44-70df009ec34ls2883086d6.0.-pod-prod-04-us; Wed, 27 Aug 2025
 15:52:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU/Pj+oRsKrEF31Exi8vAVGpnNSuTBPj6XoD6WGqm7CqgIXu58Qrwi+bV3aXRc2o+bMIOIy3nGm8DU=@googlegroups.com
X-Received: by 2002:a05:6122:469d:b0:537:3e5b:9f66 with SMTP id 71dfb90a1353d-53c8a3f05f6mr7246005e0c.12.1756335150740;
        Wed, 27 Aug 2025 15:52:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756335150; cv=none;
        d=google.com; s=arc-20240605;
        b=eqHGJOMzoj6NJbp7xQOdkPoluE+Zxfx/4udPlMK6aJuOaLFbP9fr0CVMvfIKfNKCwW
         WRTGwdXqRviM7TIKSVaof+LEkSgiu1Gl6uNeCqMixJgBlQTC4TN9gJF8TxkWTQEdvmUP
         7MgzE1xfq2nrNPTHD/UUOrbB4RzTpgq89Jxj/YG+tmLXdCe/UXVVCyI4vWfVzX6EBjVr
         nbYhxnrpQcBeUOrLN8otyfmVpSpuiWVWGbV2aRLXi1OkqhkV3cdKHp/kVzLidMekfOOT
         KUhDm0LmNktyaY7gYpEDs3me1Plu7ACKOlegohvmgRLQLLSt2Qa4Rb6T/E/SHvww3HAN
         jrMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=vJgBl10AZNWfXOOB/pDgIkoKh9accRpxxsoejJNG8b8=;
        fh=ZUktzyWRZa2uaspypbiXbmaCvChI/7olBJzsAPh4yow=;
        b=GEvRQd+b0MWzH+dQZ6qAnMbXQLC7/Hzw7lxOH9YpoPCwaggSuwnFTFDip5n7CeGqqT
         lfDPjqsYE/wMumDeC0wxMb4apYdO0uFiJGf4y+P9iJPVpnRgqAIXXR5x9KOzmOJ1RB1s
         1it+ekhfxGZ87ipGl1e8t7TJxKQGU2q0woBtseC9chE9xkELV3GhnSC2lBkC0CmE548i
         rspaAcxp91qfgwcLbZMLiuQ6uHFJ3PPIS//OQkNGk/ZfiFQzV957s2nDM2r9RrQmxBYd
         Hqq3H/rNwHAFwX2mt/qOjqoPJex7mT6tgQX9ldkEVL/5v4MUWVdnjwoPaekuTufDQJd6
         ykFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=ZqUYD5aQ;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.12 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.12])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5442fa6d282si140367e0c.3.2025.08.27.15.52.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 27 Aug 2025 15:52:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 192.198.163.12 as permitted sender) client-ip=192.198.163.12;
X-CSE-ConnectionGUID: eZHU8jo+Q36pC30R3Sbutw==
X-CSE-MsgGUID: e2wY5CraTHeDOZE/15AK9Q==
X-IronPort-AV: E=McAfee;i="6800,10657,11535"; a="62418161"
X-IronPort-AV: E=Sophos;i="6.18,217,1751266800"; 
   d="scan'208";a="62418161"
Received: from orviesa003.jf.intel.com ([10.64.159.143])
  by fmvoesa106.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Aug 2025 15:52:29 -0700
X-CSE-ConnectionGUID: 3xdHidK7Tq+UjmDsKE0yNA==
X-CSE-MsgGUID: CnrtJs0bTmqQznqiw11SnA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,217,1751266800"; 
   d="scan'208";a="174125255"
Received: from dwesterg-mobl1.amr.corp.intel.com (HELO [10.125.109.56]) ([10.125.109.56])
  by ORVIESA003-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Aug 2025 15:52:28 -0700
Message-ID: <ab1e0119-85a6-4b2e-a734-275b43e6dac4@intel.com>
Date: Wed, 27 Aug 2025 15:52:27 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v1 04/36] x86/Kconfig: drop superfluous "select
 SPARSEMEM_VMEMMAP"
To: David Hildenbrand <david@redhat.com>, linux-kernel@vger.kernel.org
Cc: "Mike Rapoport (Microsoft)" <rppt@kernel.org>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
 Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>,
 Johannes Weiner <hannes@cmpxchg.org>, John Hubbard <jhubbard@nvidia.com>,
 kasan-dev@googlegroups.com, kvm@vger.kernel.org,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, linux-arm-kernel@axis.com,
 linux-arm-kernel@lists.infradead.org, linux-crypto@vger.kernel.org,
 linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-scsi@vger.kernel.org, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Marco Elver <elver@google.com>, Marek Szyprowski <m.szyprowski@samsung.com>,
 Michal Hocko <mhocko@suse.com>, Muchun Song <muchun.song@linux.dev>,
 netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
 Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
 Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
 virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
 wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-5-david@redhat.com>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <20250827220141.262669-5-david@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=ZqUYD5aQ;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 192.198.163.12 as
 permitted sender) smtp.mailfrom=dave.hansen@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On 8/27/25 15:01, David Hildenbrand wrote:
> Now handled by the core automatically once SPARSEMEM_VMEMMAP_ENABLE
> is selected.

Acked-by: Dave Hansen <dave.hansen@linux.intel.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ab1e0119-85a6-4b2e-a734-275b43e6dac4%40intel.com.
