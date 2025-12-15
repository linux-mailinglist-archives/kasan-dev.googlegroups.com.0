Return-Path: <kasan-dev+bncBCQYDA7264GRBGPFQHFAMGQEFI4GODQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E5C7CBFCB4
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 21:42:03 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-88a25a341ebsf55689956d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 12:42:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765831322; cv=pass;
        d=google.com; s=arc-20240605;
        b=kkRSnJUncumnEIdtM+QmWRtTG90zb9NMMjFgkvKJtb7HaLTgOy4zXWn8ocShZmOCgM
         2DDT7/zvPWv++LifVDjHayT6ElmNiRblgBeZEJpdXS7hvEnc8IKyt66O7Qp3xAkrXOre
         HjgzKS1UGtMZow9y5zXuJOTBwAxLmpQAnC4T8xzhMaLTEWJl2Zw9v2132aw9v74WifuB
         8WkIHn1jDlGZUQBC52lhwgnKObgW+eL38WB8bJhJ1rGBup6fEmpuq9KPrMQK4eRZ1aAc
         YtpT0GumavRae9Mgs4bKGJ4eCkr+caI4z0vhNSuD1u5W0g/fhS3N+SXZUumexsCMUHxf
         b+zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-disposition
         :in-reply-to:mime-version:references:message-id:subject:cc:to:from
         :date:dkim-signature;
        bh=zwnPTgdVY/Eg8RT8k5kXc7FsPU+DRhdeyFwM21bdT30=;
        fh=Pho2I0N4gyj4JjXepfcwCyzVp/oQmFo8+VkJwz2Q/5U=;
        b=fyx/vv3D/5uMtmH1ZSx/vQ2ZYkWyWM7I54PPst2Jyfr29jl84ai3Pp1PYwm3qMzrY7
         jDj+OfHXySmLTe3yTZ+Bftc1lQ0TUdbFfiHbbsiK3VRReGmEPh8Wfa6XDV9AR48+h7p9
         IyR8NufH41rFuClyPmM4M/taiEU7pwR7S7PpNNi9iyDBG5X8AZCWSma7npWwsg/U7fPS
         8YxvPJNgDnb109IbkyzH7KjSr9FpAvM+J8g7RAORnCcqUeivIM7r9QARMCDCNCAc6Tre
         m5uDV0uQiskZEgVlSsQ7ENiqWDWzGTXUMbmzGOeqBGPycrNkoqhVpqp44fGA7UtZ5GdN
         CdfQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QYINGqbb;
       spf=pass (google.com: domain of mst@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=mst@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765831322; x=1766436122; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-disposition:in-reply-to:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=zwnPTgdVY/Eg8RT8k5kXc7FsPU+DRhdeyFwM21bdT30=;
        b=J9/hekKek/wQfZ8sC61+KdDulDpniybb0s1HSBQeq/ti76na/gECkIHA+rbUmldos2
         M/vkOB655YHKwxUvaonN+znPDAbRYCrAPAwIwqT3kiuma+ka9NH/8tsTi3LXK+yOPQLE
         tceNuQKeIGUuNE1hLdWZ4YmRW5WVLA7VuRppPS//cMKZ+bpNB/1xlyKG8duQswasZV8M
         c8buFjiohKBRdJm59lxwo6szmV2n2CwzQlLz57SuGmX0N1Ut5PfvKMUXSHtr9WD9nfXc
         svdIR9lzjW5Y9G8D36jBFew+PdHP7j+cs/OTfP2gRdHp1udcRqdMeXkB/uxDqLW86DPK
         3uNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765831322; x=1766436122;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-disposition:in-reply-to:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-gg:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=zwnPTgdVY/Eg8RT8k5kXc7FsPU+DRhdeyFwM21bdT30=;
        b=dLbV6QkUM+23pAhbEx1MQTECkk0Iy/g5W2FeRO+fLIotydOLqcFN6TfQpXOQ+gs3yx
         Q+PLrPC3aJaBKh7Rm2Xq/U4PVaBeQT/cA+xNUx3dMw5JJoWuvafoUm+isaXQqMK//TYr
         N2nCm5AYrkmaTU3rjEBo1NEybRtuVLrCTz3jF8EYYIFWkJdzMg31Zypotn1JWFoW1t3a
         tHy9otrhLqC5aajkmDfSCdHFr7UqKpFJ7JIJSXQyUBhhEQ2WOYPd8RbrCBrAAFXqPv6A
         UeC7rFEaRNEGbuNY1E8jL25/sv4eyplXYPLBukiXCH/c4e4n4Y7jXxlTUF6BtlfseCPr
         3oaw==
X-Forwarded-Encrypted: i=2; AJvYcCX/00WyZRkCaemGT2kiUVFGcgx0OMLnpXgfwVMLBDKctxtP6+hVzeZmoDEfQ7AnqiOLQt7n+Q==@lfdr.de
X-Gm-Message-State: AOJu0YzMK9HN8S3kQHLjQ4VJj2p6zfSrRR+r1NE2tMunRJec6e2JDb5P
	hAAHHy0/Nz2QkMbtU4bBoQnjFy3aA7qFYP60LU0caq7xfWWPUSwN2d9/
X-Google-Smtp-Source: AGHT+IF59U7x1IlRdjnoJTg1vSvJVPQjTIVUjRTmZ3rZ6qUx1ny9NIOpkXD8T480V/Bmz3cpIZmDXw==
X-Received: by 2002:a0c:f202:0:b0:880:54eb:f675 with SMTP id 6a1803df08f44-8887e19cac3mr167647396d6.67.1765831321971;
        Mon, 15 Dec 2025 12:42:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYiUF+5u0kMNJxIycQ42DX37ouM1MBmDAS4zHcrNRyoaA=="
Received: by 2002:a05:6214:300e:b0:882:63fc:f004 with SMTP id
 6a1803df08f44-8887d004267ls73925696d6.2.-pod-prod-03-us; Mon, 15 Dec 2025
 12:42:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWA8NZanGrqb7xdYNldfg1tBNN1WqjmbrcM4vjrC7oI1oJhq+zy1Z7/9yRbRdM3lIOF7aOdNSavoU4=@googlegroups.com
X-Received: by 2002:a05:6214:2304:b0:888:6fa6:782b with SMTP id 6a1803df08f44-8887e084a86mr184169856d6.30.1765831321000;
        Mon, 15 Dec 2025 12:42:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765831320; cv=none;
        d=google.com; s=arc-20240605;
        b=jv0hkdfTRE6eRCNhHvukWMwYhHl0rHJjZHAwgGmzcqGth2N2tHpjteQEhOpmoPKUfs
         y6geZynRR0lC/mW01yHZXT4k4JjY2GTMGksDCjd8iYlgo/nk+WgXjc3DsZsUFUvcSlaz
         qRPpizssNpZwUMOt+BXTvRV8VWoguTULvFFoePlYMW4TFJ+DvUgP/FZhl0DDAW2SI9Np
         8kNljXvyjT4hU0NwysQelkOaychDEWQjA2dD/RYJhI/Rv0OEDnf1NJ+2E93TOCftuqFD
         MlC2m3JOB/4f8LT1dUWL0sgM4LoHUVbv8AyLqZatG5eALofXyUx5+/wcec3tJyByH5fC
         9Agg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-disposition:in-reply-to:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=vIugujDFg05cEDjSFPsNuy7/nXwlnSCGQEq9oeQZt8U=;
        fh=QTGHv1Mk3/PGUdveJQWyGwVHO6QCF3I86iIBdIJMG7Q=;
        b=fxkIAF+6V3+f1GJOAz09ArbFtgg8hKmfHfwxCdJxTvXqC8A18Yr1grFpfp3n4thltn
         jhyDDTRHfra4vlLisBACVF8UnANjZZcAiHZTVphi5w+oIs6tpCDgoLJmozGBKQZy6B25
         B8zcBDckmdH65hqDS0oiyB4TeS4ZfBOtABXdWAEtrNW7VajoCpO3oQ3/zAMR0x8KoaRs
         Kkzqz8aNOlDs8jD89KDZ/sL68r1vYztnFu/SgQOpYIf7mBtm7u8YaI7rA8c2MGS1HOzd
         Wk/lxIbwFus60inczIQCLZx1bj8lCeRli9W3qsJr1tJXv1/7qpB16QYrAKrzLysJOJf8
         PzxQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QYINGqbb;
       spf=pass (google.com: domain of mst@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=mst@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8be31c5c61asi1099185a.6.2025.12.15.12.42.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 12:42:00 -0800 (PST)
Received-SPF: pass (google.com: domain of mst@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f70.google.com (mail-wm1-f70.google.com
 [209.85.128.70]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-36-0hY6OPODNuCWgZ6A9Z27_Q-1; Mon, 15 Dec 2025 15:41:59 -0500
X-MC-Unique: 0hY6OPODNuCWgZ6A9Z27_Q-1
X-Mimecast-MFC-AGG-ID: 0hY6OPODNuCWgZ6A9Z27_Q_1765831318
Received: by mail-wm1-f70.google.com with SMTP id 5b1f17b1804b1-47910af0c8bso29564035e9.2
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 12:41:59 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX/b4In51GNOCy5/OcSFoH6Rr1N8LI0eDqZXGp4iTfA4Zp5eUy8pqWrvrqnIGywuR7f4df+pIlInVo=@googlegroups.com
X-Gm-Gg: AY/fxX7fs3UYaL7q1rN6X2aucHJc2sqqeKPXvcgLmRAXiu2lzcVSQon1XtCdM7sGcxh
	NFfAU0NcYV3pr4v1CbU7Jx1cGi2Fp6jj+9M7nZK9Rd+gXIlSN9pDOB9iw2rG+AniBRMQTDqg+AK
	7iGAiiOPZ8NGmlCRrnzLZN75kYJorAw0FNIhRqXEWNCIuVCtELh9cbY49tlb6H3NrBrf5sG0b8l
	zVabUDux55OT9BRd6A9IMmUagYHjiKHOAaIKR2MrcLgginHW8lHphkufux11LHXWskGblB8F3x9
	AI3620sZubKdxtk0qD0Kj+Diqy61IMoGG1R+KhZjT1BlHb0uPBmmXbZvy+wdgVeQ4qthRWha4Xq
	Ia1iY/12Zam/xwyI1yMNBdNRtILr55YecPg==
X-Received: by 2002:a05:600c:6290:b0:477:76bf:e1fb with SMTP id 5b1f17b1804b1-47a8f8cdfd1mr164694515e9.16.1765831318215;
        Mon, 15 Dec 2025 12:41:58 -0800 (PST)
X-Received: by 2002:a05:600c:6290:b0:477:76bf:e1fb with SMTP id 5b1f17b1804b1-47a8f8cdfd1mr164694005e9.16.1765831317597;
        Mon, 15 Dec 2025 12:41:57 -0800 (PST)
Received: from redhat.com (IGLD-80-230-31-118.inter.net.il. [80.230.31.118])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-47a8f6f26ebsm211656485e9.14.2025.12.15.12.41.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 12:41:56 -0800 (PST)
Date: Mon, 15 Dec 2025 15:41:49 -0500
From: "'Michael S. Tsirkin' via kasan-dev" <kasan-dev@googlegroups.com>
To: Bagas Sanjaya <bagasdotme@gmail.com>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux AMDGPU <amd-gfx@lists.freedesktop.org>,
	Linux DRI Development <dri-devel@lists.freedesktop.org>,
	Linux Filesystems Development <linux-fsdevel@vger.kernel.org>,
	Linux Media <linux-media@vger.kernel.org>,
	linaro-mm-sig@lists.linaro.org, kasan-dev@googlegroups.com,
	Linux Virtualization <virtualization@lists.linux.dev>,
	Linux Memory Management List <linux-mm@kvack.org>,
	Linux Network Bridge <bridge@lists.linux.dev>,
	Linux Networking <netdev@vger.kernel.org>,
	Harry Wentland <harry.wentland@amd.com>,
	Leo Li <sunpeng.li@amd.com>, Rodrigo Siqueira <siqueira@igalia.com>,
	Alex Deucher <alexander.deucher@amd.com>,
	Christian =?iso-8859-1?Q?K=F6nig?= <christian.koenig@amd.com>,
	David Airlie <airlied@gmail.com>, Simona Vetter <simona@ffwll.ch>,
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
	Maxime Ripard <mripard@kernel.org>,
	Thomas Zimmermann <tzimmermann@suse.de>,
	Matthew Brost <matthew.brost@intel.com>,
	Danilo Krummrich <dakr@kernel.org>,
	Philipp Stanner <phasta@kernel.org>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
	Sumit Semwal <sumit.semwal@linaro.org>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	Eugenio =?iso-8859-1?Q?P=E9rez?= <eperezma@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>,
	Nikolay Aleksandrov <razor@blackwall.org>,
	Ido Schimmel <idosch@nvidia.com>,
	"David S. Miller" <davem@davemloft.net>,
	Eric Dumazet <edumazet@google.com>,
	Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>,
	Simon Horman <horms@kernel.org>,
	Taimur Hassan <Syed.Hassan@amd.com>, Wayne Lin <Wayne.Lin@amd.com>,
	Alex Hung <alex.hung@amd.com>,
	Aurabindo Pillai <aurabindo.pillai@amd.com>,
	Dillon Varone <Dillon.Varone@amd.com>,
	George Shen <george.shen@amd.com>, Aric Cyr <aric.cyr@amd.com>,
	Cruise Hung <Cruise.Hung@amd.com>,
	Mario Limonciello <mario.limonciello@amd.com>,
	Sunil Khatri <sunil.khatri@amd.com>,
	Dominik Kaszewski <dominik.kaszewski@amd.com>,
	David Hildenbrand <david@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Max Kellermann <max.kellermann@ionos.com>,
	"Nysal Jan K.A." <nysal@linux.ibm.com>,
	Ryan Roberts <ryan.roberts@arm.com>,
	Alexey Skidanov <alexey.skidanov@intel.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Kent Overstreet <kent.overstreet@linux.dev>,
	Vitaly Wool <vitaly.wool@konsulko.se>,
	Harry Yoo <harry.yoo@oracle.com>, Mateusz Guzik <mjguzik@gmail.com>,
	NeilBrown <neil@brown.name>, Amir Goldstein <amir73il@gmail.com>,
	Jeff Layton <jlayton@kernel.org>, Ivan Lipski <ivan.lipski@amd.com>,
	Tao Zhou <tao.zhou1@amd.com>, YiPeng Chai <YiPeng.Chai@amd.com>,
	Hawking Zhang <Hawking.Zhang@amd.com>,
	Lyude Paul <lyude@redhat.com>,
	Daniel Almeida <daniel.almeida@collabora.com>,
	Luben Tuikov <luben.tuikov@amd.com>,
	Matthew Auld <matthew.auld@intel.com>,
	Roopa Prabhu <roopa@cumulusnetworks.com>,
	Mao Zhu <zhumao001@208suo.com>,
	Shaomin Deng <dengshaomin@cdjrlc.com>,
	Charles Han <hanchunchao@inspur.com>,
	Jilin Yuan <yuanjilin@cdjrlc.com>,
	Swaraj Gaikwad <swarajgaikwad1925@gmail.com>,
	George Anthony Vernon <contact@gvernon.com>
Subject: Re: [PATCH 06/14] virtio: Describe @map and @vmap members in
 virtio_device struct
Message-ID: <20251215154141-mutt-send-email-mst@kernel.org>
References: <20251215113903.46555-1-bagasdotme@gmail.com>
 <20251215113903.46555-7-bagasdotme@gmail.com>
MIME-Version: 1.0
In-Reply-To: <20251215113903.46555-7-bagasdotme@gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: -MKz_kgAryhWHrGaLDpOOesY5r7F1Ah_lnCsX_bDxRI_1765831318
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: mst@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=QYINGqbb;
       spf=pass (google.com: domain of mst@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=mst@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: "Michael S. Tsirkin" <mst@redhat.com>
Reply-To: "Michael S. Tsirkin" <mst@redhat.com>
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

On Mon, Dec 15, 2025 at 06:38:54PM +0700, Bagas Sanjaya wrote:
> Sphinx reports kernel-doc warnings:
> 
> WARNING: ./include/linux/virtio.h:181 struct member 'map' not described in 'virtio_device'
> WARNING: ./include/linux/virtio.h:181 struct member 'vmap' not described in 'virtio_device'
> 
> Describe these members.
> 
> Fixes: bee8c7c24b7373 ("virtio: introduce map ops in virtio core")
> Signed-off-by: Bagas Sanjaya <bagasdotme@gmail.com>

Acked-by: Michael S. Tsirkin <mst@redhat.com>

> ---
>  include/linux/virtio.h | 2 ++
>  1 file changed, 2 insertions(+)
> 
> diff --git a/include/linux/virtio.h b/include/linux/virtio.h
> index 132a474e59140a..68ead8fda9c921 100644
> --- a/include/linux/virtio.h
> +++ b/include/linux/virtio.h
> @@ -150,11 +150,13 @@ struct virtio_admin_cmd {
>   * @id: the device type identification (used to match it with a driver).
>   * @config: the configuration ops for this device.
>   * @vringh_config: configuration ops for host vrings.
> + * @map: configuration ops for device's mapping buffer
>   * @vqs: the list of virtqueues for this device.
>   * @features: the 64 lower features supported by both driver and device.
>   * @features_array: the full features space supported by both driver and
>   *		    device.
>   * @priv: private pointer for the driver's use.
> + * @vmap: device virtual map
>   * @debugfs_dir: debugfs directory entry.
>   * @debugfs_filter_features: features to be filtered set by debugfs.
>   */
> -- 
> An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251215154141-mutt-send-email-mst%40kernel.org.
