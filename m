Return-Path: <kasan-dev+bncBAABBRXJQ7FAMGQEL4RCSQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 79901CC58D6
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 01:09:44 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-2a089575ab3sf49777795ad.0
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 16:09:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765930183; cv=pass;
        d=google.com; s=arc-20240605;
        b=Hu3XmHxEEM7T6LI10aYsfyd/ixZI8KcVuNlOJ3vfOTyhbO2yAO/ke5kiUPu4yoe7cQ
         x9w2FuJC1PV1FJqAgx98IL23/WldxtScKFaMH7KhtS8g8fIGjcreQABPsARzjlifrMoe
         3Lm9c/5mDJH0FW3P0W7IP/B6EXh0PN+jvDOK22qJoOtCyZ60mmsvvD6gQUg8kQPx8Koy
         C/4xP0VPAFGfkBK37i9QiYpMcebs4dVOV4qFDLNx69j+CMHCYr1aZSO5eboFyPI8Xhjd
         jhHoeD7EffVSD9iyqrUO1nbe7N/dVtsynT6NP+31fyXZxZvmes07Crc6V2um2ck+PXSt
         avKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=aOeBx3HMImdhQnTylw3tFx4DPLktCi+aylZuM3x1SO8=;
        fh=bnMdlMi3eVy1WAfJhIvBX987ulnYrIL3LE/jjpDH3MU=;
        b=i2/vlzr/4PWw+87qOHjMJTUePjK2Ob7j0nEnom2QAPtdOAwRblNZ5Lh5xknAYnhmp/
         ykQEEK1eoMsbYUMMW8N4/uysOiFn9cnS/0glPhAKtEMOEGgnozNQx+sPRv6iGv/wL2D1
         2WUdIBd9xSPIKe8OWfyneBov03UNnM+h5ATedCLKbu8I7KpYbLdVoGZE+38BAVUCNuD3
         uyh7orj7L9V0aPbRIaiG7ki48V088YEaDt1NO8EjQYCjxi+sPYk7XbvWVv2GCUYYtxfo
         EM/McoKM+twI5IMye4FoA8CA0nWLijF72bFjuyks+H8zlG+FK7Y/wAa9aC6dxsM/F+JP
         q23Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=aNI6UMU2;
       spf=pass (google.com: domain of david@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=david@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765930183; x=1766534983; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aOeBx3HMImdhQnTylw3tFx4DPLktCi+aylZuM3x1SO8=;
        b=Swr8O9QWB/+lz0dXWrLSVvRnF+lhHOITboEwby8H8Wlmsv0HG49zhyBMOeWrxqUGMr
         7WXlerZ2YF4Qfd19wx/6WJ9c+2Zj0Ol3G4s7xK3zwHJkdhRbDABHWTFyF85WB3BpPTD+
         DBVhtEs3gcm9B/6Pfalnm2c/Thpf3rP7M5X8b+63P05rHivCnhXW/azdV/tKwXp2QDl1
         N2TMVfDkRAVJSlOelsAlR0VmQrdiJ5hZKhKL+tjjH0U2Tz15rezjB45+CSSrcEZphmlt
         JFkkjBsc9wItnOszR4YVidDd/jvszB1hHPDrojufUPtFgeMxhZOUbOcMkPVZPovhTEXn
         UyKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765930183; x=1766534983;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=aOeBx3HMImdhQnTylw3tFx4DPLktCi+aylZuM3x1SO8=;
        b=lV10xSrzAaktSKWOMHq2REHNI+OryNM5blDRRQxYLbEJ9fHd9X5P12jx9cFCJ7IieG
         WDTlnYH4Af88cYwoJiPEbd9POEYkIWuh3HCV/HS99FcT37jzvlZkWFp0ymQYM6tv4Qd8
         twNCF3yX63s5FTafVM9WXB+uDSu3YxZUD7D61H/f/U93ulgOk22leqBJ1kevqk/cALT+
         Gh0s8VSGYJoGQjzrKz3VHjl/JJd8GK8vUw+Zbkes6mFbOEepR+Dgp+qroU9o/BaO+iit
         27o6RF1hhONjWDg+Ixn971mHGAtamy0jLPnLR88CuFnlV/Qx6YxM5sV8zqfjenOLa8V/
         ZE0Q==
X-Forwarded-Encrypted: i=2; AJvYcCUPv896Yy3kvx3zqLoSl/dmwijTSAV2v2yhdr4MQq40U5rytfJLmdblnePRV0X3ZvjvLVkxJg==@lfdr.de
X-Gm-Message-State: AOJu0YzQfgC3MzB1D5uiJnonSmE/PvEDEHF7dz2PA29aP23b1fn15QYG
	rPz3+rPj88Lh6wiY6mB0vDXKKuKYK0XFecfY3ibDTsD6GEh9e0BESS8S
X-Google-Smtp-Source: AGHT+IHieQFUpAMkjtmrnTiX+ICsxrgCfdV1S+P4gcFdEiqOPiM5bbmdijbe20EybiyHS9CNAHJp4w==
X-Received: by 2002:a17:903:320b:b0:299:e031:173 with SMTP id d9443c01a7336-29f23c7be2emr178024425ad.35.1765930182432;
        Tue, 16 Dec 2025 16:09:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWa74eGQC1KxN+YqosoBGWs8A/ZH7TtF4xzvdYhVJzLgLA=="
Received: by 2002:a17:903:200f:b0:298:e5:d986 with SMTP id d9443c01a7336-29f235ef49cls40950905ad.1.-pod-prod-09-us;
 Tue, 16 Dec 2025 16:09:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUlLk2eNHp759L2F0YsiCQb/M4QHI4vojlB5WqN5mWg9IPvob515tUekBEdQQ8dVleslnZqnJUBAEk=@googlegroups.com
X-Received: by 2002:a17:903:3b8e:b0:295:615d:f1d2 with SMTP id d9443c01a7336-29f23cd90fbmr160496065ad.48.1765930181170;
        Tue, 16 Dec 2025 16:09:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765930181; cv=none;
        d=google.com; s=arc-20240605;
        b=XQkW1tqI+gfoB8ZmuWg5muDBrQvbxcNBu9VUPnjzI2TpdO8I9rBUPEnmQZWtMX3vwi
         nghsxF9zTpbGbk0OeCRyjxW/agjebGk+x6i65Z5OEJGUnLjBwn3ZYE9cSvA24ue5Dvxq
         XZjIE+0HV881NLo49pFidV46P8WqFufmPiRdFLzwoZkdVuHfCKV69unhXHZgGv5gRjGa
         f4/xaE+80rtzxNZS+RPuZ4IOiD+MZyKcxVO+KHNx57JGBy0tpCf+SeBndfZZNl4Q8UoD
         HPeHLCFlU38LZgfSvwakww/ZzWV2b6EamVvWm5AzqGBxFULvGd5qKiykQwQqjkKvhrvj
         zo+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=2D6wcNN0uaso0Xagu6VBp+odIMbaMvcazTe0F3KqMQg=;
        fh=4SdaRA+b1wOq+ljapQKzLns7PscgKxPfxujoF1EJMIA=;
        b=fG7WYz3IBWw/muBHi4QUSxePCdZFBeB+tEMp6jmHWRjHUVNHZtIb5K8JEAmGTuIECx
         h5NU6XZeTnV8MjbuWPKhgzsPsuOFl8EPka0n1sbVSlLM2K0l2ikgeHkyNjawHiGXPbPX
         GAOHBWA3CSn2pIHUnZ1CViQZwF0XjmzZOAD9+yBDsngqY3KHELIg08lzJcarWMSXVG2A
         ZLMjnf0DzMwpedxNgL5e4d+AoakoY/D0mFf47jTSxYiAcMPUkHIRZAf0vlrvny/Bo2Ey
         lhjugkfGrW9BcVjunsRqpZqLwPGnP0ZjOY1F7dd2VAOEKDztur7KesQTUf1RY17iivS/
         B+EQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=aNI6UMU2;
       spf=pass (google.com: domain of david@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=david@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a0c94d31b1si3030225ad.3.2025.12.16.16.09.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Dec 2025 16:09:41 -0800 (PST)
Received-SPF: pass (google.com: domain of david@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id AF4EE403A5;
	Wed, 17 Dec 2025 00:09:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4CCD5C4CEF1;
	Wed, 17 Dec 2025 00:09:23 +0000 (UTC)
Message-ID: <e76e25ef-f112-4689-9753-34709613b9c2@kernel.org>
Date: Wed, 17 Dec 2025 01:09:18 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 02/14] mm: Describe @flags parameter in
 memalloc_flags_save()
To: Bagas Sanjaya <bagasdotme@gmail.com>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 Linux AMDGPU <amd-gfx@lists.freedesktop.org>,
 Linux DRI Development <dri-devel@lists.freedesktop.org>,
 Linux Filesystems Development <linux-fsdevel@vger.kernel.org>,
 Linux Media <linux-media@vger.kernel.org>, linaro-mm-sig@lists.linaro.org,
 kasan-dev@googlegroups.com,
 Linux Virtualization <virtualization@lists.linux.dev>,
 Linux Memory Management List <linux-mm@kvack.org>,
 Linux Network Bridge <bridge@lists.linux.dev>,
 Linux Networking <netdev@vger.kernel.org>
Cc: Harry Wentland <harry.wentland@amd.com>, Leo Li <sunpeng.li@amd.com>,
 Rodrigo Siqueira <siqueira@igalia.com>,
 Alex Deucher <alexander.deucher@amd.com>,
 =?UTF-8?Q?Christian_K=C3=B6nig?= <christian.koenig@amd.com>,
 David Airlie <airlied@gmail.com>, Simona Vetter <simona@ffwll.ch>,
 Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
 Maxime Ripard <mripard@kernel.org>, Thomas Zimmermann <tzimmermann@suse.de>,
 Matthew Brost <matthew.brost@intel.com>, Danilo Krummrich <dakr@kernel.org>,
 Philipp Stanner <phasta@kernel.org>, Alexander Viro
 <viro@zeniv.linux.org.uk>, Christian Brauner <brauner@kernel.org>,
 Jan Kara <jack@suse.cz>, Sumit Semwal <sumit.semwal@linaro.org>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, "Michael S. Tsirkin" <mst@redhat.com>,
 Jason Wang <jasowang@redhat.com>, Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
 =?UTF-8?Q?Eugenio_P=C3=A9rez?= <eperezma@redhat.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 Nikolay Aleksandrov <razor@blackwall.org>, Ido Schimmel <idosch@nvidia.com>,
 "David S. Miller" <davem@davemloft.net>, Eric Dumazet <edumazet@google.com>,
 Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>,
 Simon Horman <horms@kernel.org>, Taimur Hassan <Syed.Hassan@amd.com>,
 Wayne Lin <Wayne.Lin@amd.com>, Alex Hung <alex.hung@amd.com>,
 Aurabindo Pillai <aurabindo.pillai@amd.com>,
 Dillon Varone <Dillon.Varone@amd.com>, George Shen <george.shen@amd.com>,
 Aric Cyr <aric.cyr@amd.com>, Cruise Hung <Cruise.Hung@amd.com>,
 Mario Limonciello <mario.limonciello@amd.com>,
 Sunil Khatri <sunil.khatri@amd.com>,
 Dominik Kaszewski <dominik.kaszewski@amd.com>,
 Peter Zijlstra <peterz@infradead.org>,
 Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Max Kellermann <max.kellermann@ionos.com>,
 "Nysal Jan K.A." <nysal@linux.ibm.com>, Ryan Roberts <ryan.roberts@arm.com>,
 Alexey Skidanov <alexey.skidanov@intel.com>, Vlastimil Babka
 <vbabka@suse.cz>, Kent Overstreet <kent.overstreet@linux.dev>,
 Vitaly Wool <vitaly.wool@konsulko.se>, Harry Yoo <harry.yoo@oracle.com>,
 Mateusz Guzik <mjguzik@gmail.com>, NeilBrown <neil@brown.name>,
 Amir Goldstein <amir73il@gmail.com>, Jeff Layton <jlayton@kernel.org>,
 Ivan Lipski <ivan.lipski@amd.com>, Tao Zhou <tao.zhou1@amd.com>,
 YiPeng Chai <YiPeng.Chai@amd.com>, Hawking Zhang <Hawking.Zhang@amd.com>,
 Lyude Paul <lyude@redhat.com>, Daniel Almeida
 <daniel.almeida@collabora.com>, Luben Tuikov <luben.tuikov@amd.com>,
 Matthew Auld <matthew.auld@intel.com>,
 Roopa Prabhu <roopa@cumulusnetworks.com>, Mao Zhu <zhumao001@208suo.com>,
 Shaomin Deng <dengshaomin@cdjrlc.com>, Charles Han <hanchunchao@inspur.com>,
 Jilin Yuan <yuanjilin@cdjrlc.com>,
 Swaraj Gaikwad <swarajgaikwad1925@gmail.com>,
 George Anthony Vernon <contact@gvernon.com>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
 <20251215113903.46555-3-bagasdotme@gmail.com>
From: "'David Hildenbrand (Red Hat)' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: en-US
In-Reply-To: <20251215113903.46555-3-bagasdotme@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=aNI6UMU2;       spf=pass
 (google.com: domain of david@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=david@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "David Hildenbrand (Red Hat)" <david@kernel.org>
Reply-To: "David Hildenbrand (Red Hat)" <david@kernel.org>
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

On 12/15/25 12:38, Bagas Sanjaya wrote:
> Sphinx reports kernel-doc warning:
> 
> WARNING: ./include/linux/sched/mm.h:332 function parameter 'flags' not described in 'memalloc_flags_save'
> 
> Describe @flags to fix it.
> 
> Fixes: 3f6d5e6a468d02 ("mm: introduce memalloc_flags_{save,restore}")
> Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>
> ---
>   include/linux/sched/mm.h | 1 +
>   1 file changed, 1 insertion(+)
> 
> diff --git a/include/linux/sched/mm.h b/include/linux/sched/mm.h
> index 0e1d73955fa511..95d0040df58413 100644
> --- a/include/linux/sched/mm.h
> +++ b/include/linux/sched/mm.h
> @@ -325,6 +325,7 @@ static inline void might_alloc(gfp_t gfp_mask)
>   
>   /**
>    * memalloc_flags_save - Add a PF_* flag to current->flags, save old value
> + * @flags: Flags to add.
>    *
>    * This allows PF_* flags to be conveniently added, irrespective of current
>    * value, and then the old version restored with memalloc_flags_restore().

Acked-by: David Hildenbrand (Red Hat) <david@kernel.org>

-- 
Cheers

David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e76e25ef-f112-4689-9753-34709613b9c2%40kernel.org.
